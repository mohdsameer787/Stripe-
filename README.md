package main

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/stripe/stripe-go/v76"
	"github.com/stripe/stripe-go/v76/balancetransaction"
	"github.com/stripe/stripe-go/v76/checkout/session"
	"github.com/stripe/stripe-go/v76/event"
	"github.com/stripe/stripe-go/v76/paymentintent"
	"github.com/stripe/stripe-go/v76/transfer"
)

// ==========================
// Models
// ==========================

type EscrowStatus string

const (
	StatusPending  EscrowStatus = "PENDING"
	StatusOnHold   EscrowStatus = "ON_HOLD"   // dispute/refund
	StatusPaidOut  EscrowStatus = "PAID_OUT"
	StatusCanceled EscrowStatus = "CANCELED"  // refunded before payout
)

type Escrow struct {
	ID              uint          `gorm:"primaryKey" json:"id"`
	CreatedAt       time.Time     `json:"created_at"`
	UpdatedAt       time.Time     `json:"updated_at"`

	OrderID         string        `gorm:"index" json:"order_id"`
	BuyerEmail      string        `json:"buyer_email"`
	SellerAccountID string        `gorm:"index" json:"seller_account_id"` // acct_***
	StripePI        string        `gorm:"uniqueIndex" json:"stripe_pi"`   // pi_***
	CheckoutSession string        `gorm:"uniqueIndex" json:"checkout_session"` // cs_***

	Currency        string        `json:"currency"`
	AmountTotal     int64         `json:"amount_total"`
	AppFeeAmount    int64         `json:"app_fee_amount"`

	ReleaseAfter    time.Time     `json:"release_after"`
	Status          EscrowStatus  `gorm:"index" json:"status"`
	TransferID      string        `json:"transfer_id"`
	Notes           string        `json:"notes"`
}

type Order struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`

	OrderID     string    `gorm:"uniqueIndex" json:"order_id"`
	BuyerID     string    `json:"buyer_id"`
	ProductName string    `json:"product_name"`
	Quantity    int64     `json:"quantity"`
	Price       int64     `json:"price"`      // per item in minor units
	Currency    string    `json:"currency"`
	Status      string    `json:"status"`     // e.g., DRAFT, PENDING, PAID, FULFILLED
}

// ==========================
// Config
// ==========================

type Config struct {
	StripeSecretKey     string
	StripeWebhookSecret string
	Port                string
	FrontendURL         string
	PayoutDelay         time.Duration
	AdminAPIKey         string // simple auth for admin endpoints
}

var (
	db  *gorm.DB
	cfg Config
)

func mustEnv(key string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		log.Fatalf("missing env %s", key)
	}
	return v
}

func getEnvDefault(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func getEnvDurationDefault(key string, def time.Duration) time.Duration {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if d, err := time.ParseDuration(v); err == nil { return d }
	}
	return def
}

func loadConfig() Config {
	return Config{
		StripeSecretKey:     mustEnv("STRIPE_SECRET_KEY"),
		StripeWebhookSecret: mustEnv("STRIPE_WEBHOOK_SECRET"),
		Port:                getEnvDefault("PORT", "8080"),
		FrontendURL:         getEnvDefault("FRONTEND_URL", "http://localhost:3000"),
		PayoutDelay:         getEnvDurationDefault("PAYOUT_DELAY", 7*24*time.Hour),
		AdminAPIKey:         getEnvDefault("ADMIN_API_KEY", "changeme"),
	}
}

// ==========================
// Main
// ==========================

func main() {
	cfg = loadConfig()
	stripe.Key = cfg.StripeSecretKey

	var err error
	db, err = gorm.Open(sqlite.Open("escrow.db"), &gorm.Config{})
	if err != nil { log.Fatal(err) }
	if err := db.AutoMigrate(&Order{}, &Escrow{}); err != nil { log.Fatal(err) }

	e := echo.New()
	e.HideBanner = true
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions},
		AllowHeaders: []string{"*"},
	}))

	// Public endpoints
	e.POST("/api/orders", handleCreateOrder)                                 // create an order in our DB
	e.POST("/api/create-checkout-session", handleCreateCheckoutSession)      // start Stripe Checkout for an order
	e.POST("/api/stripe/webhook", handleStripeWebhook)                        // Stripe webhooks

	// Merchant (seller) endpoints
	e.GET("/api/merchant/escrows/:accountID", handleGetMerchantEscrows)
	e.GET("/api/merchant/orders-with-escrow/:accountID", handleGetMerchantOrdersWithEscrow)

	// Admin endpoints (simple API key auth)
	admin := e.Group("/api/admin", apiKeyMiddleware(cfg.AdminAPIKey))
	admin.GET("/escrows", handleGetAllEscrows)
	admin.GET("/orders", handleGetAllOrders)
	admin.GET("/orders-with-escrow", handleGetOrdersWithEscrow)

	// Start background worker for auto-payouts
	go startPayoutWorker()

	log.Printf("server running on :%s", cfg.Port)
	if err := e.Start(":" + cfg.Port); err != nil { log.Fatal(err) }
}

// ==========================
// Orders
// ==========================

type CreateOrderReq struct {
	OrderID     string `json:"order_id"`
	BuyerID     string `json:"buyer_id"`
	ProductName string `json:"product_name"`
	Quantity    int64  `json:"quantity"`
	Price       int64  `json:"price"`
	Currency    string `json:"currency"`
}

func handleCreateOrder(c echo.Context) error {
	var req CreateOrderReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "invalid payload"})
	}
	if req.OrderID == "" || req.ProductName == "" || req.Price <= 0 || req.Quantity <= 0 || req.Currency == "" {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "missing required fields"})
	}
	ord := Order{
		OrderID:     req.OrderID,
		BuyerID:     req.BuyerID,
		ProductName: req.ProductName,
		Quantity:    req.Quantity,
		Price:       req.Price,
		Currency:    strings.ToLower(req.Currency),
		Status:      "PENDING",
	}
	if err := db.Create(&ord).Error; err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, ord)
}

func handleGetAllOrders(c echo.Context) error {
	var orders []Order
	if err := db.Order("created_at desc").Find(&orders).Error; err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, orders)
}

// ==========================
// Checkout Session (Escrow mode)
// ==========================

type CreateSessionReq struct {
	OrderID         string `json:"order_id"`
	SellerAccountID string `json:"seller_account_id"` // acct_***
	Amount          int64  `json:"amount"`            // per unit in minor units
	Currency        string `json:"currency"`
	ProductName     string `json:"product_name"`
	Quantity        int64  `json:"quantity"`
	AppFeeAmount    int64  `json:"app_fee_amount"`
	BuyerEmail      string `json:"buyer_email"`
}

func handleCreateCheckoutSession(c echo.Context) error {
	var req CreateSessionReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "invalid payload"})
	}
	if req.SellerAccountID == "" || req.Amount <= 0 || req.Currency == "" || req.ProductName == "" || req.OrderID == "" {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "missing required fields"})
	}
	if req.Quantity == 0 { req.Quantity = 1 }

	params := &stripe.CheckoutSessionParams{
		PaymentMethodTypes: stripe.StringSlice([]string{"card"}),
		Mode:              stripe.String(string(stripe.CheckoutSessionModePayment)),
		SuccessURL:        stripe.String(cfg.FrontendURL + "/success?session_id={CHECKOUT_SESSION_ID}"),
		CancelURL:         stripe.String(cfg.FrontendURL + "/cancel"),
		CustomerEmail:     stripe.String(req.BuyerEmail),
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			{
				PriceData: &stripe.CheckoutSessionLineItemPriceDataParams{
					Currency: stripe.String(strings.ToLower(req.Currency)),
					ProductData: &stripe.CheckoutSessionLineItemPriceDataProductDataParams{
						Name: stripe.String(req.ProductName),
					},
					UnitAmount: stripe.Int64(req.Amount),
				},
				Quantity: stripe.Int64(req.Quantity),
			},
		},
	}

	// Escrow flow: no TransferData here → funds go to platform balance first
	params.PaymentIntentData = &stripe.CheckoutSessionPaymentIntentDataParams{
		ApplicationFeeAmount: stripe.Int64(req.AppFeeAmount),
	}

	s, err := session.New(params)
	if err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": err.Error()})
	}

	// Pre-create escrow record (will attach PI on webhook)
	rec := Escrow{
		OrderID:         req.OrderID,
		BuyerEmail:      req.BuyerEmail,
		SellerAccountID: req.SellerAccountID,
		CheckoutSession: s.ID,
		Currency:        strings.ToLower(req.Currency),
		AmountTotal:     req.Amount * req.Quantity,
		AppFeeAmount:    req.AppFeeAmount,
		ReleaseAfter:    time.Now().Add(cfg.PayoutDelay),
		Status:          StatusPending,
	}
	if err := db.Create(&rec).Error; err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": err.Error()})
	}

	// Optional: mark order as PAID_PENDING in your system
	db.Model(&Order{}).Where("order_id = ?", req.OrderID).Update("status", "PAYMENT_PENDING")

	return c.JSON(http.StatusOK, echo.Map{"id": s.ID, "url": s.URL})
}

// ==========================
// Stripe Webhook
// ==========================

func handleStripeWebhook(c echo.Context) error {
	// Read raw body (Echo may have already consumed it if not careful)
	buf := new(strings.Builder)
	if _, err := buf.ReadFrom(c.Request().Body); err != nil {
		return c.NoContent(http.StatusBadRequest)
	}
	payload := []byte(buf.String())

	sigHeader := c.Request().Header.Get("Stripe-Signature")
	eventObj, err := event.ConstructEvent(payload, sigHeader, cfg.StripeWebhookSecret)
	if err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "signature verification failed"})
	}

	switch eventObj.Type {
	case "checkout.session.completed":
		var s stripe.CheckoutSession
		if err := json.Unmarshal(eventObj.Data.Raw, &s); err != nil {
			return c.NoContent(http.StatusBadRequest)
		}
		if s.PaymentIntent != nil {
			// Attach PI and push out release timer from completion time
			db.Model(&Escrow{}).Where("checkout_session = ?", s.ID).Updates(map[string]interface{}{
				"stripe_pi":     *s.PaymentIntent,
				"release_after": time.Now().Add(cfg.PayoutDelay),
			})
			// mark order as PAID
			db.Model(&Order{}).Where("order_id = ?", s.ClientReferenceID).Update("status", "PAID")
		}

	case "charge.refunded":
		var ch stripe.Charge
		if err := json.Unmarshal(eventObj.Data.Raw, &ch); err == nil {
			if ch.PaymentIntent != nil {
				db.Model(&Escrow{}).Where("stripe_pi = ? AND status = ?", *ch.PaymentIntent, StatusPending).Update("status", StatusCanceled)
				// Optional: set related order status
				var esc Escrow
				db.Where("stripe_pi = ?", *ch.PaymentIntent).First(&esc)
				db.Model(&Order{}).Where("order_id = ?", esc.OrderID).Update("status", "REFUNDED")
			}
		}

	case "charge.dispute.created":
		// put escrow on hold
		var d struct{ PaymentIntent string `json:"payment_intent"` }
		_ = json.Unmarshal(eventObj.Data.Raw, &d)
		if d.PaymentIntent != "" {
			db.Model(&Escrow{}).Where("stripe_pi = ? AND status = ?", d.PaymentIntent, StatusPending).Update("status", StatusOnHold)
		}
	}

	return c.NoContent(http.StatusOK)
}

// ==========================
// Payout Worker
// ==========================

func startPayoutWorker() {
	t := time.NewTicker(1 * time.Minute)
	defer t.Stop()
	for range t.C {
		processDuePayouts()
	}
}

func processDuePayouts() {
	var escrows []Escrow
	if err := db.Where("status = ? AND release_after <= ?", StatusPending, time.Now()).Find(&escrows).Error; err != nil {
		log.Printf("query due escrows error: %v", err)
		return
	}
	for _, e := range escrows {
		if err := payOutEscrow(e); err != nil {
			log.Printf("payout failed for escrow %d: %v", e.ID, err)
			continue
		}
	}
}

func payOutEscrow(e Escrow) error {
	if e.SellerAccountID == "" || e.StripePI == "" { return nil }

	// 1) Fetch PI -> charge -> balance transaction to calculate fees
	pi, err := paymentintent.Get(e.StripePI, nil)
	if err != nil { return err }
	if pi.Charges == nil || len(pi.Charges.Data) == 0 { return nil }
	ch := pi.Charges.Data[0]
	if ch.BalanceTransaction == nil { return nil }

	bt, err := balancetransaction.Get(ch.BalanceTransaction.ID, nil)
	if err != nil { return err }

	gross := bt.Amount   // total captured
	stripeFee := bt.Fee  // Stripe processing fee
	net := bt.Net        // gross - fee (what landed in platform balance)

	// Policy: seller gets net - appFee (platform absorbs Stripe fees)
	amountToSeller := net - e.AppFeeAmount
	if amountToSeller < 0 { amountToSeller = 0 }

	// 2) Create transfer to seller's Connect account
	params := &stripe.TransferParams{
		Amount:           stripe.Int64(amountToSeller),
		Currency:         stripe.String(strings.ToLower(e.Currency)),
		Destination:      stripe.String(e.SellerAccountID),
		SourceTransaction: stripe.String(ch.ID), // for traceability
	}
	tr, err := transfer.New(params)
	if err != nil { return err }

	// 3) Mark escrow paid out
	if err := db.Model(&Escrow{}).Where("id = ?", e.ID).Updates(map[string]interface{}{
		"status":      StatusPaidOut,
		"transfer_id": tr.ID,
		"notes":       notesFromFees(gross, stripeFee, net, e.AppFeeAmount, amountToSeller),
	}).Error; err != nil { return err }

	// Optional: update order status to FULFILLED if you use delivery confirmation, etc.
	return nil
}

func notesFromFees(gross, fee, net, appFee, toSeller int64) string {
	return strings.Join([]string{
		"gross=", itoa(gross),
		" fee=", itoa(fee),
		" net=", itoa(net),
		" appFee=", itoa(appFee),
		" toSeller=", itoa(toSeller),
	}, "")
}

func itoa(v int64) string { return fmtInt(v) }

// minimal int64->string to avoid fmt
func fmtInt(i int64) string {
	neg := i < 0
	if neg { i = -i }
	var b [32]byte
	bp := len(b)
	for i >= 10 {
		q := i / 10
		r := i - q*10
		bp--
		b[bp] = byte('0' + r)
		i = q
	}
	bp--
	b[bp] = byte('0' + i)
	if neg { bp--; b[bp] = '-' }
	return string(b[bp:])
}

// ==========================
// Queries for Frontends
// ==========================

func handleGetAllEscrows(c echo.Context) error {
	var escrows []Escrow
	if err := db.Order("created_at desc").Find(&escrows).Error; err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, escrows)
}

func handleGetMerchantEscrows(c echo.Context) error {
	accountID := c.Param("accountID")
	var escrows []Escrow
	if err := db.Where("seller_account_id = ?", accountID).Order("created_at desc").Find(&escrows).Error; err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, escrows)
}

// Combined views (Orders + Escrow)

type OrderWithEscrow struct {
	Order  Order  `json:"order"`
	Escrow Escrow `json:"escrow"`
}

func handleGetOrdersWithEscrow(c echo.Context) error {
	var orders []Order
	if err := db.Order("created_at desc").Find(&orders).Error; err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": err.Error()})
	}
	var result []OrderWithEscrow
	for _, o := range orders {
		var e Escrow
		db.Where("order_id = ?", o.OrderID).First(&e)
		result = append(result, OrderWithEscrow{Order: o, Escrow: e})
	}
	return c.JSON(http.StatusOK, result)
}

func handleGetMerchantOrdersWithEscrow(c echo.Context) error {
	accountID := c.Param("accountID")
	var escrows []Escrow
	if err := db.Where("seller_account_id = ?", accountID).Order("created_at desc").Find(&escrows).Error; err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": err.Error()})
	}
	var result []OrderWithEscrow
	for _, e := range escrows {
		var o Order
		db.Where("order_id = ?", e.OrderID).First(&o)
		result = append(result, OrderWithEscrow{Order: o, Escrow: e})
	}
	return c.JSON(http.StatusOK, result)
}

// ==========================
// Simple Admin API key middleware
// ==========================

func apiKeyMiddleware(expected string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			apiKey := c.Request().Header.Get("x-api-key")
			if subtle.ConstantTimeCompare([]byte(apiKey), []byte(expected)) != 1 {
				return c.JSON(http.StatusUnauthorized, echo.Map{"error": "unauthorized"})
			}
			return next(c)
		}
	}
}

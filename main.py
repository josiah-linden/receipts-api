from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from typing import List, Optional
import os
import uuid
import stripe
import hmac
import hashlib
import base64
import time

app = FastAPI(title="Receipts API")

# -------------------------
# CORS (for CodeSandbox / browsers)
# -------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # demo: allow any origin
    allow_methods=["*"],
    allow_headers=["*"],
)

# Extra: force CORS header on ALL responses (belt + suspenders)
@app.middleware("http")
async def add_cors_headers(request: Request, call_next):
    # Handle preflight explicitly
    if request.method == "OPTIONS":
        resp = JSONResponse({"ok": True})
    else:
        resp = await call_next(request)

    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "*"
    return resp

# -------------------------
# In-memory storage (NO DB)
# -------------------------
transactions: List[dict] = []

# -------------------------
# Stripe setup
# -------------------------
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
if not STRIPE_SECRET_KEY:
    print("WARNING: STRIPE_SECRET_KEY not set")

stripe.api_key = STRIPE_SECRET_KEY

# -------------------------
# Square setup (webhooks)
# -------------------------
# In Square Developer Dashboard -> Webhooks, you'll see a "Webhook Signature Key"
SQUARE_WEBHOOK_SIGNATURE_KEY = os.getenv("SQUARE_WEBHOOK_SIGNATURE_KEY")
if not SQUARE_WEBHOOK_SIGNATURE_KEY:
    print("WARNING: SQUARE_WEBHOOK_SIGNATURE_KEY not set (Square webhooks will be accepted without verification)")

def _square_expected_signature(signature_key: str, notification_url: str, body_bytes: bytes) -> str:
    """
    Square signature = base64( HMAC-SHA1(signature_key, notification_url + body) )
    """
    message = (notification_url or "").encode("utf-8") + (body_bytes or b"")
    digest = hmac.new(signature_key.encode("utf-8"), message, hashlib.sha1).digest()
    return base64.b64encode(digest).decode("utf-8")

def _request_public_url(request: Request) -> str:
    """
    Build the exact public URL Square posted to.
    NOTE: If you're behind a proxy, we prefer X-Forwarded-* headers.
    """
    headers = request.headers
    proto = headers.get("x-forwarded-proto") or request.url.scheme
    host = headers.get("x-forwarded-host") or headers.get("host") or request.url.hostname or ""
    path = request.url.path
    query = request.url.query
    return f"{proto}://{host}{path}" + (f"?{query}" if query else "")

# -------------------------
# Stripe Webhook
# -------------------------
@app.post("/webhooks/stripe")
async def stripe_webhook(request: Request):
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="Missing STRIPE_SECRET_KEY")

    event = await request.json()

    # We only care about completed checkouts for demo
    if event.get("type") != "checkout.session.completed":
        return {"ok": True, "ignored": True}

    session = event["data"]["object"]
    user_id = session.get("client_reference_id") or "demo_user"

    # Pull itemized line items from Stripe
    line_items = stripe.checkout.Session.list_line_items(session["id"])

    items = []
    for li in line_items.data:
        items.append(
            {
                "sku": li.price.product if li.price else None,
                "name": li.description,
                "quantity": li.quantity,
                "unit_price": ((li.price.unit_amount or 0) / 100) if li.price else 0,
            }
        )

    transaction = {
        "id": str(uuid.uuid4()),
        "user_id": user_id,
        "merchant": "stripe",
        "payment_id": session.get("payment_intent"),
        "timestamp": session.get("created"),
        "currency": (session.get("currency") or "usd").upper(),
        "total": (session.get("amount_total") or 0) / 100,
        "items": items,
    }

    transactions.append(transaction)
    return {"ok": True}

# -------------------------
# Square Webhook (NEW) - does NOT affect existing API
# URL you saved in Square: https://receipts-api-9owj.onrender.com/api/webhooks/square
# -------------------------
@app.post("/api/webhooks/square")
async def square_webhook(request: Request):
    # Read raw body (needed for signature verification + logging)
    body_bytes = await request.body()

    # Parse JSON if possible (Square sends JSON)
    try:
        payload = await request.json()
    except Exception:
        payload = None

    # Verify signature if key is set
    if SQUARE_WEBHOOK_SIGNATURE_KEY:
        notification_url = _request_public_url(request)
        expected = _square_expected_signature(SQUARE_WEBHOOK_SIGNATURE_KEY, notification_url, body_bytes)
        provided = request.headers.get("x-square-hmacsha1-signature") or ""

        if not hmac.compare_digest(expected, provided):
            # For now, reject invalid signatures (this is important in production)
            raise HTTPException(status_code=401, detail="Invalid Square webhook signature")

    # Log receipt (so you can confirm it's working in Render logs)
    event_type = payload.get("type") if isinstance(payload, dict) else None
    print("✅ Square webhook received")
    print("Type:", event_type)
    # Don’t spam logs with giant payloads—just show keys
    if isinstance(payload, dict):
        print("Payload keys:", list(payload.keys()))
    else:
        print("Raw body length:", len(body_bytes or b""))

    # Demo behavior: optionally convert Square event -> a transaction record your app can display.
    # We'll keep this minimal to avoid breaking anything; we only append when we have enough data.
    if isinstance(payload, dict):
        data = payload.get("data") or {}
        obj = data.get("object") or {}

        # Try to capture a payment if present
        square_payment = obj.get("payment") if isinstance(obj, dict) else None
        square_order = obj.get("order") if isinstance(obj, dict) else None

        # In Square, user identity isn’t inherent—use a fixed demo user for now
        user_id = "demo_user"

        # If payment exists, create a simple "receipt" entry.
        # We'll enrich this in the next step by fetching order line items via Square API (server-side).
        if isinstance(square_payment, dict):
            amount_money = square_payment.get("amount_money") or {}
            total = (amount_money.get("amount") or 0) / 100
            currency = (amount_money.get("currency") or "USD").upper()

            transaction = {
                "id": str(uuid.uuid4()),
                "user_id": user_id,
                "merchant": "square",
                "payment_id": square_payment.get("id"),
                "timestamp": int(time.time()),
                "currency": currency,
                "total": total,
                "items": [],  # next step: populate from order line items
            }

            transactions.append(transaction)

        # If only an order exists (no payment in this webhook), we just acknowledge for now.
        # Next step: we’ll choose events + pull line items properly.

    return {"ok": True}

# -------------------------
# API your app calls
# -------------------------
@app.get("/api/transactions")
def get_transactions(user_id: Optional[str] = None):
    if user_id:
        return [t for t in transactions if t.get("user_id") == user_id]
    return transactions

# -------------------------
# Health check
# -------------------------
@app.get("/")
def health():
    return {"status": "ok"}

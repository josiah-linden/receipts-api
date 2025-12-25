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

# Dedupe storage for webhook events (in-memory)
processed_square_event_ids: set[str] = set()

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
# Optional: verify Square webhook signature
SQUARE_WEBHOOK_SIGNATURE_KEY = os.getenv("SQUARE_WEBHOOK_SIGNATURE_KEY")
if not SQUARE_WEBHOOK_SIGNATURE_KEY:
    print("WARNING: SQUARE_WEBHOOK_SIGNATURE_KEY not set (Square webhooks will NOT be verified)")

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
    Prefer X-Forwarded-* headers if behind proxy (Render).
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
# Square Webhook (FIXED)
# - Dedupe by event_id
# - Only create receipts from order.created (has the real line items)
# - Ignore noisy updated events for now to prevent duplicates
# -------------------------
@app.post("/api/webhooks/square")
async def square_webhook(request: Request):
    body_bytes = await request.body()

    # Parse JSON
    try:
        payload = await request.json()
    except Exception:
        payload = None

    # Verify signature if configured
    if SQUARE_WEBHOOK_SIGNATURE_KEY:
        notification_url = _request_public_url(request)
        expected = _square_expected_signature(SQUARE_WEBHOOK_SIGNATURE_KEY, notification_url, body_bytes)
        provided = request.headers.get("x-square-hmacsha1-signature") or ""
        if not hmac.compare_digest(expected, provided):
            raise HTTPException(status_code=401, detail="Invalid Square webhook signature")

    if not isinstance(payload, dict):
        # Always return 200 so Square doesn't retry forever
        print("⚠️ Square webhook: non-JSON payload")
        return {"ok": True}

    event_type = payload.get("type")
    event_id = payload.get("event_id")

    print("✅ Square webhook received")
    print("Type:", event_type)
    print("Payload keys:", list(payload.keys()))

    # Dedupe retries / multi-delivery
    if event_id and event_id in processed_square_event_ids:
        print("↩️ Duplicate Square event_id ignored:", event_id)
        return {"ok": True, "deduped": True}
    if event_id:
        processed_square_event_ids.add(event_id)

    # Only create a receipt when we get the real order with line items
    if event_type != "order.created":
        return {"ok": True, "ignored": True}

    data = payload.get("data") or {}
    obj = data.get("object") or {}
    order = obj.get("order") if isinstance(obj, dict) else None

    if not isinstance(order, dict):
        return {"ok": True, "ignored": True}

    # Square order fields
    order_id = order.get("id")
    location_id = order.get("location_id")
    created_at = order.get("created_at")  # ISO timestamp string
    line_items = order.get("line_items") or []

    # Totals
    total_money = order.get("total_money") or {}
    currency = (total_money.get("currency") or "USD").upper()
    total = (total_money.get("amount") or 0) / 100

    # Build item lines
    items = []
    if isinstance(line_items, list):
        for li in line_items:
            if not isinstance(li, dict):
                continue
            name = li.get("name") or "Item"
            qty_str = li.get("quantity") or "1"
            try:
                quantity = float(qty_str)
                # Your app likely expects int-ish; keep it simple
                if quantity.is_integer():
                    quantity = int(quantity)
            except Exception:
                quantity = 1

            # Square can put pricing in a few places
            base_price = li.get("base_price_money") or {}
            unit_price = (base_price.get("amount") or 0) / 100

            variation_name = li.get("variation_name")
            if variation_name:
                display_name = f"{name} ({variation_name})"
            else:
                display_name = name

            items.append(
                {
                    "sku": li.get("catalog_object_id"),  # may be None
                    "name": display_name,
                    "quantity": quantity,
                    "unit_price": unit_price,
                }
            )

    # IMPORTANT: for now we keep user_id demo_user (matches your app polling)
    # Later we can set user_id from metadata, customer, or checkout reference.
    transaction = {
        "id": str(uuid.uuid4()),
        "user_id": "demo_user",
        "merchant": "square",
        "payment_id": order_id,             # store order_id here for now
        "timestamp": int(time.time()),      # simple epoch
        "currency": currency,
        "total": total,
        "items": items,
        "meta": {
            "square_event": event_type,
            "square_event_id": event_id,
            "square_order_id": order_id,
            "square_location_id": location_id,
            "square_created_at": created_at,
        },
    }

    # Extra protection: avoid duplicate receipts for the same order_id
    if order_id:
        for t in transactions:
            if t.get("merchant") == "square" and t.get("meta", {}).get("square_order_id") == order_id:
                print("↩️ Duplicate Square order ignored:", order_id)
                return {"ok": True, "deduped_order": True}

    transactions.append(transaction)
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

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
from datetime import datetime

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

# Dedupe Square delivery retries (in-memory)
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
SQUARE_WEBHOOK_SIGNATURE_KEY = os.getenv("SQUARE_WEBHOOK_SIGNATURE_KEY")
if not SQUARE_WEBHOOK_SIGNATURE_KEY:
    print("WARNING: SQUARE_WEBHOOK_SIGNATURE_KEY not set (Square webhooks will NOT be verified)")

def _square_expected_signature(signature_key: str, notification_url: str, body_bytes: bytes) -> str:
    message = (notification_url or "").encode("utf-8") + (body_bytes or b"")
    digest = hmac.new(signature_key.encode("utf-8"), message, hashlib.sha1).digest()
    return base64.b64encode(digest).decode("utf-8")

def _request_public_url(request: Request) -> str:
    headers = request.headers
    proto = headers.get("x-forwarded-proto") or request.url.scheme
    host = headers.get("x-forwarded-host") or headers.get("host") or request.url.hostname or ""
    path = request.url.path
    query = request.url.query
    return f"{proto}://{host}{path}" + (f"?{query}" if query else "")

def _iso_to_epoch(iso_str: Optional[str]) -> Optional[int]:
    if not iso_str:
        return None
    try:
        # Handles "2025-12-25T20:00:00Z" style
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return int(dt.timestamp())
    except Exception:
        return None

def _square_money_to_float(m: dict) -> float:
    if not isinstance(m, dict):
        return 0.0
    return (m.get("amount") or 0) / 100

def _extract_square_order(obj: dict) -> Optional[dict]:
    """
    Square webhooks wrap the entity under data.object.order (for order.* events)
    """
    if not isinstance(obj, dict):
        return None
    order = obj.get("order")
    if isinstance(order, dict):
        return order
    return None

def _extract_line_items(order: dict) -> list:
    line_items = order.get("line_items") or []
    items = []
    if not isinstance(line_items, list):
        return items

    for li in line_items:
        if not isinstance(li, dict):
            continue
        name = li.get("name") or "Item"
        variation_name = li.get("variation_name")
        display_name = f"{name} ({variation_name})" if variation_name else name

        qty_str = li.get("quantity") or "1"
        try:
            q = float(qty_str)
            quantity = int(q) if q.is_integer() else q
        except Exception:
            quantity = 1

        base_price = li.get("base_price_money") or {}
        unit_price = _square_money_to_float(base_price)

        items.append(
            {
                "sku": li.get("catalog_object_id"),  # may be None
                "name": display_name,
                "quantity": quantity,
                "unit_price": unit_price,
            }
        )
    return items

def _find_square_tx_by_order_id(order_id: str) -> Optional[dict]:
    for t in transactions:
        if t.get("merchant") == "square" and t.get("meta", {}).get("square_order_id") == order_id:
            return t
    return None

# -------------------------
# Stripe Webhook
# -------------------------
@app.post("/webhooks/stripe")
async def stripe_webhook(request: Request):
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="Missing STRIPE_SECRET_KEY")

    event = await request.json()

    if event.get("type") != "checkout.session.completed":
        return {"ok": True, "ignored": True}

    session = event["data"]["object"]
    user_id = session.get("client_reference_id") or "demo_user"

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
# Square Webhook (UPDATED)
# - Create or update ONE receipt per order across order.created/order.updated
# - Dedupe by event_id
# -------------------------
@app.post("/api/webhooks/square")
async def square_webhook(request: Request):
    body_bytes = await request.body()

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
        print("⚠️ Square webhook: non-JSON payload")
        return {"ok": True}

    event_type = payload.get("type")
    event_id = payload.get("event_id")

    print("✅ Square webhook received")
    print("Type:", event_type)
    print("Payload keys:", list(payload.keys()))

    # Dedupe (Square can retry delivery)
    if event_id and event_id in processed_square_event_ids:
        print("↩️ Duplicate Square event_id ignored:", event_id)
        return {"ok": True, "deduped": True}
    if event_id:
        processed_square_event_ids.add(event_id)

    # We only build receipts from order.* events (these contain line items / totals)
    if event_type not in ("order.created", "order.updated"):
        return {"ok": True, "ignored": True}

    data = payload.get("data") or {}
    obj = data.get("object") or {}
    if not isinstance(obj, dict):
        return {"ok": True, "ignored": True}

    order = _extract_square_order(obj)
    if not isinstance(order, dict):
        return {"ok": True, "ignored": True}

    order_id = order.get("id")
    if not order_id:
        return {"ok": True, "ignored": True}

    # Extract what we can now (created often has partial data; updated usually has full)
    location_id = order.get("location_id")
    created_at_iso = order.get("created_at")
    epoch = _iso_to_epoch(created_at_iso) or int(time.time())

    total_money = order.get("total_money") or {}
    currency = (total_money.get("currency") or "USD").upper()
    total = _square_money_to_float(total_money)

    items = _extract_line_items(order)

    existing = _find_square_tx_by_order_id(order_id)

    # If this is the first time we see this order, create a placeholder receipt
    if not existing:
        tx = {
            "id": str(uuid.uuid4()),
            "user_id": "demo_user",   # matches your app polling
            "merchant": "square",
            "payment_id": order_id,   # store order_id here for now
            "timestamp": epoch,
            "currency": currency,
            "total": total,
            "items": items,
            "meta": {
                "square_order_id": order_id,
                "square_location_id": location_id,
                "square_created_at": created_at_iso,
                "square_last_event": event_type,
                "square_last_event_id": event_id,
            },
        }
        transactions.append(tx)
        print("✅ Square receipt created for order:", order_id)
        return {"ok": True, "created": True}

    # Otherwise update the existing receipt with any new info we got
    # Only overwrite if we actually have better data (items or total)
    if items:
        existing["items"] = items
    if total > 0:
        existing["total"] = total
    if currency:
        existing["currency"] = currency
    if epoch:
        existing["timestamp"] = epoch

    if "meta" not in existing or not isinstance(existing["meta"], dict):
        existing["meta"] = {}
    existing["meta"].update(
        {
            "square_location_id": location_id or existing["meta"].get("square_location_id"),
            "square_created_at": created_at_iso or existing["meta"].get("square_created_at"),
            "square_last_event": event_type,
            "square_last_event_id": event_id,
        }
    )

    print("✅ Square receipt updated for order:", order_id)
    return {"ok": True, "updated": True}

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

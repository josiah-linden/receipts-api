from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import os
import json
import time
import uuid
import hmac
import hashlib
import base64
import urllib.request
from typing import List, Optional, Dict
from urllib.parse import urlencode

app = FastAPI(title="Receipts Ingestion API (Stripe + Square)")

# -------------------------
# In-memory state (temporary)
# -------------------------
transactions: List[dict] = []
processed_square_event_ids = set()
square_oauth_tokens: Dict[str, dict] = {}

# -------------------------
# Helpers
# -------------------------
def _money_to_float(money: dict) -> float:
    try:
        return (money.get("amount") or 0) / 100.0
    except Exception:
        return 0.0

def _request_public_url(request: Request) -> str:
    # Try to construct a public URL for webhook signature verification.
    # Prefer explicit env var SQUARE_WEBHOOK_NOTIFICATION_URL when set.
    scheme = request.headers.get("x-forwarded-proto") or request.url.scheme
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
    path = request.url.path
    return f"{scheme}://{host}{path}"

# -------------------------
# Stripe
# -------------------------
import stripe

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
if not STRIPE_SECRET_KEY:
    print("WARNING: STRIPE_SECRET_KEY not set")
stripe.api_key = STRIPE_SECRET_KEY

# -------------------------
# Square
# -------------------------
SQUARE_WEBHOOK_SIGNATURE_KEY = os.getenv("SQUARE_WEBHOOK_SIGNATURE_KEY")
if not SQUARE_WEBHOOK_SIGNATURE_KEY:
    print("WARNING: SQUARE_WEBHOOK_SIGNATURE_KEY not set (Square webhooks will NOT be verified)")

SQUARE_ACCESS_TOKEN = os.getenv("SQUARE_ACCESS_TOKEN")
if not SQUARE_ACCESS_TOKEN:
    print("WARNING: SQUARE_ACCESS_TOKEN not set (Square enrichment will be skipped)")

SQUARE_API_BASE = "https://connect.squareup.com"

def _square_expected_signature(signature_key: str, notification_url: str, body_bytes: bytes) -> str:
    message = (notification_url or "").encode("utf-8") + (body_bytes or b"")
    digest = hmac.new(signature_key.encode("utf-8"), message, hashlib.sha256).digest()
    return base64.b64encode(digest).decode("utf-8")
    
def _square_request(path: str, method: str = "GET", body: Optional[dict] = None) -> dict:
    if not SQUARE_ACCESS_TOKEN:
        raise RuntimeError("Square access token missing")

    url = f"{SQUARE_API_BASE}{path}"
    data = None
    headers = {"Authorization": f"Bearer {SQUARE_ACCESS_TOKEN}", "Content-Type": "application/json", "Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read().decode("utf-8") or "{}"
            return json.loads(raw)
    except urllib.error.HTTPError as e:
        try:
            err = e.read().decode("utf-8")
        except Exception:
            err = str(e)
        print("Square API error:", e.code, err)
        return {"error": True, "status": e.code, "detail": err}
    except Exception as e:
        print("Square API request failed:", str(e))
        return {"error": True, "detail": str(e)}

def _square_get_order(order_id: str) -> Optional[dict]:
    if not order_id:
        return None
    resp = _square_request(f"/v2/orders/{order_id}", method="GET")
    if isinstance(resp, dict) and resp.get("order"):
        return resp.get("order")
    return None

def _square_get_catalog_object(object_id: str) -> Optional[dict]:
    if not object_id:
        return None
    resp = _square_request(f"/v2/catalog/object/{object_id}", method="GET")
    if isinstance(resp, dict) and resp.get("object"):
        return resp.get("object")
    return None

def _order_to_items(order: dict) -> List[dict]:
    """
    Convert Square Order object to our items format:
      { sku, name, quantity, unit_price }
    """
    items: List[dict] = []

    # Primary: order.line_items
    line_items = order.get("line_items") or []
    if isinstance(line_items, list) and line_items:
        for li in line_items:
            if not isinstance(li, dict):
                continue
            name = li.get("name") or ""
            quantity = li.get("quantity") or "1"
            try:
                quantity_f = float(quantity)
            except Exception:
                quantity_f = 1.0
            base_price_money = (li.get("base_price_money") or {})
            unit_price = _money_to_float(base_price_money)

            # SKU resolution (best-effort)
            sku = li.get("sku") or None
            catalog_object_id = li.get("catalog_object_id") or li.get("variation_id")
            if not sku and catalog_object_id:
                obj = _square_get_catalog_object(catalog_object_id)
                if isinstance(obj, dict):
                    item_data = (obj.get("item_variation_data") or {})
                    sku = item_data.get("sku") or sku

            items.append(
                {
                    "sku": sku,
                    "name": name,
                    "quantity": quantity_f if quantity_f.is_integer() else quantity_f,
                    "unit_price": unit_price,
                }
            )
        return items

    # Fallback: Square Websites can sometimes place items under fulfillments shipment_details
    fulfillments = order.get("fulfillments") or []
    if isinstance(fulfillments, list):
        for f in fulfillments:
            if not isinstance(f, dict):
                continue
            ship = (f.get("shipment_details") or {})
            ship_items = ship.get("line_items") or []
            if not isinstance(ship_items, list):
                continue
            for li in ship_items:
                if not isinstance(li, dict):
                    continue
                name = li.get("name") or ""
                quantity = li.get("quantity") or "1"
                try:
                    quantity_f = float(quantity)
                except Exception:
                    quantity_f = 1.0
                base_price_money = (li.get("base_price_money") or {})
                unit_price = _money_to_float(base_price_money)
                sku = li.get("sku") or None

                catalog_object_id = li.get("catalog_object_id") or li.get("variation_id")
                if not sku and catalog_object_id:
                    obj = _square_get_catalog_object(catalog_object_id)
                    if isinstance(obj, dict):
                        item_data = (obj.get("item_variation_data") or {})
                        sku = item_data.get("sku") or sku

                items.append(
                    {
                        "sku": sku,
                        "name": name,
                        "quantity": quantity_f if quantity_f.is_integer() else quantity_f,
                        "unit_price": unit_price,
                    }
                )

    return items

def _find_square_tx_by_payment_id(payment_id: str) -> Optional[dict]:
    for t in reversed(transactions):
        if t.get("merchant") == "square" and t.get("payment_id") == payment_id:
            return t
    return None

# -------------------------
# Square OAuth (minimal)
# -------------------------
SQUARE_APPLICATION_ID = os.getenv("SQUARE_APPLICATION_ID")
SQUARE_APPLICATION_SECRET = os.getenv("SQUARE_APPLICATION_SECRET")
SQUARE_REDIRECT_URL = os.getenv("SQUARE_REDIRECT_URL")  # e.g. https://yourdomain.com/square/callback

@app.get("/square/connect")
async def square_connect():
    if not SQUARE_APPLICATION_ID or not SQUARE_REDIRECT_URL:
        raise HTTPException(status_code=500, detail="Square OAuth env vars missing")

    # NOTE: scopes trimmed for this demo; adjust as needed.
    scopes = [
        "PAYMENTS_READ",
        "ORDERS_READ",
        "CUSTOMERS_READ",
        "ITEMS_READ",
        "MERCHANT_PROFILE_READ",
    ]
    params = {
        "client_id": SQUARE_APPLICATION_ID,
        "scope": " ".join(scopes),
        "session": "false",
        "redirect_uri": SQUARE_REDIRECT_URL,
    }
    url = f"https://connect.squareup.com/oauth2/authorize?{urlencode(params)}"
    return JSONResponse({"url": url})

@app.get("/square/callback")
async def square_callback(code: str):
    if not SQUARE_APPLICATION_ID or not SQUARE_APPLICATION_SECRET or not SQUARE_REDIRECT_URL:
        raise HTTPException(status_code=500, detail="Square OAuth env vars missing")

    body = {
        "client_id": SQUARE_APPLICATION_ID,
        "client_secret": SQUARE_APPLICATION_SECRET,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": SQUARE_REDIRECT_URL,
    }

    req = urllib.request.Request(
        "https://connect.squareup.com/oauth2/token",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=20) as resp:
        data = json.loads(resp.read().decode("utf-8") or "{}")

    global square_oauth_tokens
    try:
        square_oauth_tokens
    except NameError:
        square_oauth_tokens = {}

    merchant_id = data.get("merchant_id") or "unknown"
    square_oauth_tokens[merchant_id] = data

    # TEMP shortcut: use merchant token for enrichment
    global SQUARE_ACCESS_TOKEN
    SQUARE_ACCESS_TOKEN = data.get("access_token")

    return JSONResponse({"ok": True, "merchant_id": merchant_id})

# -------------------------
# Stripe Webhook
# -------------------------
@app.post("/webhooks/stripe")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    if not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=500, detail="STRIPE_WEBHOOK_SECRET not set")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Stripe webhook error: {str(e)}")

    event_type = event["type"]

    if event_type == "checkout.session.completed":
        session = event["data"]["object"]
        user_id = session.get("client_reference_id") or "demo_user"

        line_items = stripe.checkout.Session.list_line_items(session["id"], limit=100)
        items = []
        for li in line_items.get("data", []):
            price = li.get("price") or {}
            product_name = li.get("description") or ""
            quantity = li.get("quantity") or 1
            unit_amount = (price.get("unit_amount") or 0) / 100
            items.append(
                {
                    "sku": (price.get("product") or ""),
                    "name": product_name,
                    "quantity": quantity,
                    "unit_price": unit_amount,
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
            "meta": {"stripe_session": session},
        }

        transactions.append(transaction)
        return {"ok": True}

    return {"ok": True}

# -------------------------
# Square Webhook
# -------------------------
@app.post("/api/webhooks/square")
async def square_webhook(request: Request):
    body_bytes = await request.body()

    try:
        payload = await request.json()
    except Exception:
        payload = None

    if SQUARE_WEBHOOK_SIGNATURE_KEY:
        notification_url = os.getenv("SQUARE_WEBHOOK_NOTIFICATION_URL") or _request_public_url(request)
        expected = _square_expected_signature(SQUARE_WEBHOOK_SIGNATURE_KEY, notification_url, body_bytes)
        provided = request.headers.get("x-square-hmacsha256-signature") or ""
        if not hmac.compare_digest(expected, provided):
            raise HTTPException(status_code=401, detail="Invalid Square webhook signature")

    if not isinstance(payload, dict):
        return {"ok": True}

    event_type = payload.get("type")
    event_id = payload.get("event_id")

    print("✅ Square webhook received")
    print("Type:", event_type)

    # Use the correct merchant OAuth token for Square API calls (webhook runs per-merchant)
    merchant_id = (payload or {}).get("merchant_id")
    try:
        global square_oauth_tokens
    except NameError:
        square_oauth_tokens = {}
    if merchant_id and merchant_id in square_oauth_tokens:
        global SQUARE_ACCESS_TOKEN
        tok = square_oauth_tokens[merchant_id] or {}
        SQUARE_ACCESS_TOKEN = tok.get("access_token") or SQUARE_ACCESS_TOKEN

    if event_id and event_id in processed_square_event_ids:
        return {"ok": True, "deduped_event": True}
    if event_id:
        processed_square_event_ids.add(event_id)

    data = payload.get("data") or {}
    obj = data.get("object") or {}
    if not isinstance(obj, dict):
        return {"ok": True}

    user_id = "demo_user"

    # order.updated: object is an order, not a payment
    if event_type == "order.updated":
        order = obj.get("order")
        if not isinstance(order, dict):
            return {"ok": True, "ignored": True}

        order_id = order.get("id")
        if not order_id:
            return {"ok": True, "ignored": True}

        items: List[dict] = []
        order_full = None
        if SQUARE_ACCESS_TOKEN:
            order_full = _square_get_order(order_id)
            if isinstance(order_full, dict):
                items = _order_to_items(order_full)

        # Update existing transaction (created from payment.*) by order_id
        for t in transactions:
            meta = t.get("meta") or {}
            if t.get("merchant") == "square" and meta.get("square_order_id") == order_id:
                if items:
                    t["items"] = items
                meta["square_order"] = order_full
                meta["square_event_type"] = event_type
                meta["square_event_id"] = event_id
                t["meta"] = meta
                return {"ok": True, "updated_existing": True}

        return {"ok": True, "no_matching_tx": True}

    # Treat both payment.created and payment.updated as enrichment triggers
    if event_type in ("payment.created", "payment.updated"):
        payment = obj.get("payment")
        if not isinstance(payment, dict):
            return {"ok": True, "ignored": True}

        amount_money = payment.get("amount_money") or {}
        currency = (amount_money.get("currency") or "USD").upper()
        total = _money_to_float(amount_money)

        ts = int(time.time())
        order_id = payment.get("order_id") or payment.get("associated_order_id")

        # Try to fetch the full order + item lines (often succeeds on payment.updated)
        items: List[dict] = []
        order_full = None
        if order_id and SQUARE_ACCESS_TOKEN:
            order_full = _square_get_order(order_id)
            if isinstance(order_full, dict):
                items = _order_to_items(order_full)

        payment_id = payment.get("id") or ""
        existing = _find_square_tx_by_payment_id(payment_id)
        if existing:
            if items:
                existing["items"] = items
            if order_full is not None:
                existing["meta"]["square_order"] = order_full
            existing["meta"]["square_event_type"] = event_type
            existing["meta"]["square_event_id"] = event_id
            existing["meta"]["square_order_id"] = order_id or existing["meta"].get("square_order_id")
            return {"ok": True, "updated_existing": True}

        tx = {
            "id": str(uuid.uuid4()),
            "user_id": user_id,
            "merchant": "square",
            "payment_id": payment_id,
            "timestamp": ts,
            "currency": currency,
            "total": total,
            "items": items,
            "meta": {
                "square_event_type": event_type,
                "square_event_id": event_id,
                "square_order_id": order_id,
                "square_payment": payment,
                "square_order": order_full,
            },
        }
        transactions.append(tx)
        return {"ok": True, "created": True}

    return {"ok": True, "ignored": True}

# -------------------------
# API your app calls
# -------------------------
@app.get("/api/transactions")
async def get_transactions(user_id: str = "demo_user"):
    return [t for t in transactions if t.get("user_id") == user_id]

@app.post("/api/square/backfill")
async def square_backfill(user_id: str = "demo_user", limit: int = 50):
    if not SQUARE_ACCESS_TOKEN:
        raise HTTPException(status_code=500, detail="SQUARE_ACCESS_TOKEN missing; re-connect Square OAuth first.")

    updated = 0
    checked = 0

    # newest first
    for t in reversed(transactions):
        if checked >= limit:
            break
        if t.get("user_id") != user_id:
            continue
        if t.get("merchant") != "square":
            continue

        checked += 1

        meta = t.get("meta") or {}
        order_id = meta.get("square_order_id")
        if not order_id:
            continue

        # only backfill if missing
        if t.get("items") and meta.get("square_order"):
            continue

        order_full = _square_get_order(order_id)
        if isinstance(order_full, dict):
            items = _order_to_items(order_full)
            if items:
                t["items"] = items
            meta["square_order"] = order_full
            t["meta"] = meta
            updated += 1

    return {"ok": True, "checked": checked, "updated": updated}

@app.get("/")
async def root():
    return {"ok": True, "service": "receipts-ingestion"}


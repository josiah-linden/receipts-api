from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse  # ✅ added RedirectResponse
from typing import List, Optional, Dict
import os
import uuid
import stripe
import hmac
import hashlib
import base64
import time
import json
import urllib.request
import urllib.error
from urllib.parse import urlencode  # ✅ added urlencode

app = FastAPI(title="Receipts API")

# -------------------------
# CORS
# -------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

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
# In-memory storage
# -------------------------
transactions: List[dict] = []
processed_square_event_ids: set[str] = set()
seen_square_payment_ids: set[str] = set()

# -------------------------
# Stripe
# -------------------------
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
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

def _request_public_url(request: Request) -> str:
    headers = request.headers
    proto = headers.get("x-forwarded-proto") or request.url.scheme
    host = headers.get("x-forwarded-host") or headers.get("host") or request.url.hostname or ""
    path = request.url.path
    query = request.url.query
    return f"{proto}://{host}{path}" + (f"?{query}" if query else "")

def _money_to_float(m: dict) -> float:
    if not isinstance(m, dict):
        return 0.0
    return (m.get("amount") or 0) / 100

def _square_api(method: str, path: str, body: Optional[dict] = None) -> Optional[dict]:
    if not SQUARE_ACCESS_TOKEN:
        return None

    url = f"{SQUARE_API_BASE}{path}"
    data = None
    headers = {
        "Authorization": f"Bearer {SQUARE_ACCESS_TOKEN}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        # Pick a stable version; doesn't need to be perfect for this demo
        "Square-Version": "2025-01-23",
    }
    if body is not None:
        data = json.dumps(body).encode("utf-8")

    req = urllib.request.Request(url, data=data, headers=headers, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        try:
            err = e.read().decode("utf-8")
        except Exception:
            err = str(e)
        print(f"Square API error {e.code} on {method} {path}: {err}")
        return None
    except Exception as e:
        print(f"Square API request failed on {method} {path}: {e}")
        return None

def _square_get_order(order_id: str) -> Optional[dict]:
    # Orders API: GET /v2/orders/{order_id}
    res = _square_api("GET", f"/v2/orders/{order_id}")
    if not res:
        return None
    return res.get("order")

def _square_catalog_skus_for_variations(variation_ids: List[str]) -> Dict[str, str]:
    if not variation_ids or not SQUARE_ACCESS_TOKEN:
        return {}
    ids = list(dict.fromkeys([vid for vid in variation_ids if vid]))[:200]
    res = _square_api("POST", "/v2/catalog/batch-retrieve", {"object_ids": ids, "include_related_objects": False})
    if not res or "objects" not in res:
        return {}

    out: Dict[str, str] = {}
    for obj in res.get("objects", []):
        if not isinstance(obj, dict):
            continue
        if obj.get("type") != "ITEM_VARIATION":
            continue
        oid = obj.get("id")
        data = obj.get("item_variation_data") or {}
        sku = data.get("sku")
        if oid and sku:
            out[oid] = sku
    return out

def _order_to_items(order: dict) -> List[dict]:
    line_items = order.get("line_items") or []
    if not isinstance(line_items, list):
        return []

    variation_ids: List[str] = []
    for li in line_items:
        if not isinstance(li, dict):
            continue
        vid = li.get("catalog_object_id") or li.get("variation_id")
        if vid:
            variation_ids.append(vid)

    sku_map = _square_catalog_skus_for_variations(variation_ids)

    items: List[dict] = []
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
        unit_price = _money_to_float(base_price)

        vid = li.get("catalog_object_id") or li.get("variation_id")
        sku = sku_map.get(vid) or vid  # fallback: variation id

        items.append(
            {
                "sku": sku,
                "name": display_name,
                "quantity": quantity,
                "unit_price": unit_price,
            }
        )
    return items

def _find_square_tx_by_payment_id(payment_id: str) -> Optional[dict]:
    for t in transactions:
        if t.get("merchant") == "square" and t.get("payment_id") == payment_id:
            return t
    return None

# -------------------------
# Square OAuth Connect
# -------------------------
@app.get("/square/connect")
def square_connect():
    square_app_id = os.getenv("SQUARE_APPLICATION_ID")
    square_redirect_url = os.getenv("SQUARE_REDIRECT_URL")

    if not square_app_id or not square_redirect_url:
        raise HTTPException(status_code=500, detail="Missing SQUARE_APPLICATION_ID or SQUARE_REDIRECT_URL")

    square_env = (os.getenv("SQUARE_ENV") or "production").lower()
    if square_env == "sandbox":
        base = "https://connect.squareupsandbox.com"
    else:
        base = "https://connect.squareup.com"

    scopes = " ".join([
        "ORDERS_READ",
        "PAYMENTS_READ",
    ])

    qs = urlencode({
        "client_id": square_app_id,
        "scope": scopes,
        "session": "false",
        "redirect_uri": square_redirect_url,
    })

    url = f"{base}/oauth2/authorize?{qs}"
    return RedirectResponse(url)


@app.get("/square/callback")
async def square_callback(request: Request):
    code = request.query_params.get("code")
    if not code:
        return JSONResponse({"ok": False, "query": dict(request.query_params)}, status_code=400)

    app_id = os.getenv("SQUARE_APPLICATION_ID")
    app_secret = os.getenv("SQUARE_APPLICATION_SECRET")
    redirect_url = os.getenv("SQUARE_REDIRECT_URL")
    if not app_id or not app_secret or not redirect_url:
        raise HTTPException(status_code=500, detail="Missing Square OAuth env vars")

    token_url = "https://connect.squareup.com/oauth2/token"
    payload = json.dumps({
        "client_id": app_id,
        "client_secret": app_secret,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_url,
    }).encode("utf-8")

    req = urllib.request.Request(
        token_url,
        data=payload,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=20) as resp:
        data = json.loads(resp.read().decode("utf-8") or "{}")

    # TEMP: store in memory (resets on deploy)
    global square_oauth_tokens
    try:
        square_oauth_tokens
    except NameError:
        square_oauth_tokens = {}

    merchant_id = data.get("merchant_id") or "unknown"
    square_oauth_tokens[merchant_id] = data

    # 🔑 IMPORTANT: use this merchant token for enrichment (TEMP shortcut)
    global SQUARE_ACCESS_TOKEN
    SQUARE_ACCESS_TOKEN = data.get("access_token")

    return JSONResponse({"ok": True, "merchant_id": merchant_id})

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

    line_items = stripe.checkout.Session.list_line_items(session["id"], expand=["data.price.product"])

    items = []
    for li in line_items.data:
        price = li.price
        product = getattr(price, "product", None) if price else None

        sku = None
        if price and getattr(price, "lookup_key", None):
            sku = price.lookup_key
        if not sku and isinstance(product, stripe.Product):
            sku = (product.metadata or {}).get("sku") or product.id
        elif not sku and isinstance(product, str):
            sku = product

        unit_amount = (price.unit_amount or 0) if price else 0

        items.append(
            {
                "sku": sku,
                "name": li.description,
                "quantity": li.quantity,
                "unit_price": unit_amount / 100,
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

    if event_id and event_id in processed_square_event_ids:
        return {"ok": True, "deduped_event": True}
    if event_id:
        processed_square_event_ids.add(event_id)

    data = payload.get("data") or {}
    obj = data.get("object") or {}
    if not isinstance(obj, dict):
        return {"ok": True}

    user_id = "demo_user"

   # Treat both payment.created and payment.updated as enrichment triggers
if event_type in ("payment.created", "payment.updated"):
    payment = obj.get("payment")
    if not isinstance(payment, dict):
        return {"ok": True, "ignored": True}

    payment_id = payment.get("id")
    if not payment_id:
        return {"ok": True, "ignored": True}

    amount_money = payment.get("amount_money") or {}
    currency = (amount_money.get("currency") or "USD").upper()
    total = _money_to_float(amount_money)

    ts = int(time.time())
    order_id = payment.get("order_id") or payment.get("associated_order_id")

    # Try to fetch the full order + item lines now (often succeeds on payment.updated)
    items: List[dict] = []
    order_full = None
    if order_id and SQUARE_ACCESS_TOKEN:
        order_full = _square_get_order(order_id)
        if isinstance(order_full, dict):
            items = _order_to_items(order_full)

    existing = _find_square_tx_by_payment_id(payment_id)

    # If we already created the tx on payment.created, upgrade it with items/order on update
    if existing:
        # only overwrite if we found better data
        if items:
            existing["items"] = items
        if order_full is not None:
            existing["meta"]["square_order"] = order_full
        existing["meta"]["square_event_type"] = event_type
        existing["meta"]["square_event_id"] = event_id
        return {"ok": True, "updated_existing": True}

    # Otherwise create a new one (first time we see this payment)
    tx = {
        "id": str(uuid.uuid4()),
        "user_id": "demo_user",
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

        # Try to fetch the full order + item lines right now
        items: List[dict] = []
        order_full = None
        if order_id and SQUARE_ACCESS_TOKEN:
            order_full = _square_get_order(order_id)
            if isinstance(order_full, dict):
                items = _order_to_items(order_full)

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
                "square_order": order_full,  # may be None if not fetched
            },
        }
        transactions.append(tx)
        return {"ok": True}

    return {"ok": True, "ignored": True}

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

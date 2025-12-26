from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from typing import List, Optional, Dict, Any
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

app = FastAPI(title="Receipts API")

# -------------------------
# CORS (for CodeSandbox / browsers)
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
# In-memory storage (NO DB)
# -------------------------
transactions: List[dict] = []
processed_square_event_ids: set[str] = set()
seen_square_payment_ids: set[str] = set()

# -------------------------
# Stripe setup
# -------------------------
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
if not STRIPE_SECRET_KEY:
    print("WARNING: STRIPE_SECRET_KEY not set")
stripe.api_key = STRIPE_SECRET_KEY

# -------------------------
# Square setup
# -------------------------
SQUARE_WEBHOOK_SIGNATURE_KEY = os.getenv("SQUARE_WEBHOOK_SIGNATURE_KEY")
if not SQUARE_WEBHOOK_SIGNATURE_KEY:
    print("WARNING: SQUARE_WEBHOOK_SIGNATURE_KEY not set (Square webhooks will NOT be verified)")

SQUARE_ACCESS_TOKEN = os.getenv("SQUARE_ACCESS_TOKEN")
if not SQUARE_ACCESS_TOKEN:
    print("WARNING: SQUARE_ACCESS_TOKEN not set (Square SKU enrichment will be skipped)")

SQUARE_API_BASE = "https://connect.squareup.com"

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

def _money_to_float(m: dict) -> float:
    if not isinstance(m, dict):
        return 0.0
    return (m.get("amount") or 0) / 100

def _square_api(method: str, path: str, body: Optional[dict] = None) -> Optional[dict]:
    """
    Minimal Square API client using stdlib urllib (no new requirements).
    Requires SQUARE_ACCESS_TOKEN.
    """
    if not SQUARE_ACCESS_TOKEN:
        return None

    url = f"{SQUARE_API_BASE}{path}"
    data = None
    headers = {
        "Authorization": f"Bearer {SQUARE_ACCESS_TOKEN}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Square-Version": "2025-01-23",  # safe pinned version
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

def _square_catalog_skus_for_variations(variation_ids: List[str]) -> Dict[str, str]:
    """
    Given Square Catalog object IDs (ITEM_VARIATION ids), return {variation_id: sku}
    """
    if not variation_ids or not SQUARE_ACCESS_TOKEN:
        return {}

    # Deduplicate + cap to something reasonable
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

def _find_square_tx_by_payment_id(payment_id: str) -> Optional[dict]:
    for t in transactions:
        if t.get("merchant") == "square" and t.get("payment_id") == payment_id:
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

    # Only completed checkout sessions
    if event.get("type") != "checkout.session.completed":
        return {"ok": True, "ignored": True}

    session = event["data"]["object"]
    user_id = session.get("client_reference_id") or "demo_user"

    # Pull itemized line items from Stripe
    line_items = stripe.checkout.Session.list_line_items(session["id"], expand=["data.price.product"])

    items = []
    for li in line_items.data:
        price = li.price
        product = None
        if price and hasattr(price, "product"):
            product = price.product  # expanded product or id

        # Best-effort SKU strategy:
        # 1) price.lookup_key (if you set it as SKU)
        # 2) product.metadata["sku"] (recommended)
        # 3) fallback to product id
        sku = None
        if price and getattr(price, "lookup_key", None):
            sku = price.lookup_key

        # If product is expanded object:
        if not sku and isinstance(product, stripe.Product):
            sku = (product.metadata or {}).get("sku") or product.id
        elif not sku and isinstance(product, str):
            sku = product

        unit_amount = 0
        if price and getattr(price, "unit_amount", None):
            unit_amount = price.unit_amount or 0

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
        "meta": {
            "stripe_session": session,  # full raw session payload
            "stripe_event_type": event.get("type"),
        },
    }

    transactions.append(transaction)
    return {"ok": True}

# -------------------------
# Square Webhook
# - Create on payment.created (deduped)
# - Enrich items + SKUs using order.* payload + Square Catalog API
# -------------------------
@app.post("/api/webhooks/square")
async def square_webhook(request: Request):
    body_bytes = await request.body()

    try:
        payload = await request.json()
    except Exception:
        payload = None

    # Optional signature verify
    if SQUARE_WEBHOOK_SIGNATURE_KEY:
        notification_url = _request_public_url(request)
        expected = _square_expected_signature(SQUARE_WEBHOOK_SIGNATURE_KEY, notification_url, body_bytes)
        provided = request.headers.get("x-square-hmacsha1-signature") or ""
        if not hmac.compare_digest(expected, provided):
            raise HTTPException(status_code=401, detail="Invalid Square webhook signature")

    if not isinstance(payload, dict):
        return {"ok": True}

    event_type = payload.get("type")
    event_id = payload.get("event_id")

    print("✅ Square webhook received")
    print("Type:", event_type)
    print("Payload keys:", list(payload.keys()))

    # Dedupe delivery retries
    if event_id and event_id in processed_square_event_ids:
        return {"ok": True, "deduped_event": True}
    if event_id:
        processed_square_event_ids.add(event_id)

    user_id = "demo_user"

    data = payload.get("data") or {}
    obj = data.get("object") or {}
    if not isinstance(obj, dict):
        return {"ok": True, "ignored": True}

    # ---- payment.created: create a receipt record (so app always shows something)
    if event_type == "payment.created":
        payment = obj.get("payment")
        if not isinstance(payment, dict):
            return {"ok": True, "ignored": True}

        payment_id = payment.get("id")
        if not payment_id:
            return {"ok": True, "ignored": True}

        # Dedup per payment id
        if payment_id in seen_square_payment_ids or _find_square_tx_by_payment_id(payment_id):
            return {"ok": True, "deduped_payment": True}
        seen_square_payment_ids.add(payment_id)

        amount_money = payment.get("amount_money") or {}
        currency = (amount_money.get("currency") or "USD").upper()
        total = _money_to_float(amount_money)
        created_at_iso = payment.get("created_at")
        ts = int(time.time())

        order_id = payment.get("order_id") or payment.get("associated_order_id")

        tx = {
            "id": str(uuid.uuid4()),
            "user_id": user_id,
            "merchant": "square",
            "payment_id": payment_id,
            "timestamp": ts,
            "currency": currency,
            "total": total,
            "items": [],
            "meta": {
                "square_event_type": event_type,
                "square_event_id": event_id,
                "square_payment": payment,   # full raw payment payload
                "square_order_id": order_id,
            },
        }
        transactions.append(tx)
        return {"ok": True, "created": True}

    # ---- order.created / order.updated: enrich the receipt with itemized lines + SKUs
    if event_type in ("order.created", "order.updated"):
        order = obj.get("order")
        if not isinstance(order, dict):
            return {"ok": True, "ignored": True}

        order_id = order.get("id")
        if not order_id:
            return {"ok": True, "ignored": True}

        # Build itemized lines from order payload
        line_items = order.get("line_items") or []
        variation_ids: List[str] = []
        items: List[dict] = []

        if isinstance(line_items, list):
            for li in line_items:
                if not isinstance(li, dict):
                    continue
                # In Square orders, catalog_object_id is typically the ITEM_VARIATION id
                variation_id = li.get("catalog_object_id") or li.get("variation_id")
                if variation_id:
                    variation_ids.append(variation_id)

        sku_map = _square_catalog_skus_for_variations(variation_ids)

        if isinstance(line_items, list):
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

                variation_id = li.get("catalog_object_id") or li.get("variation_id")
                sku = sku_map.get(variation_id) or variation_id  # fallback to variation id

                items.append(
                    {
                        "sku": sku,
                        "name": display_name,
                        "quantity": quantity,
                        "unit_price": unit_price,
                    }
                )

        total_money = order.get("total_money") or {}
        currency = (total_money.get("currency") or "USD").upper()
        total = _money_to_float(total_money)

        # Attach to an existing Square payment receipt if we can find it by order_id in meta
        # (we stored order_id on payment.created if it existed)
        target = None
        for t in reversed(transactions):
            if t.get("merchant") != "square":
                continue
            if t.get("meta", {}).get("square_order_id") == order_id:
                target = t
                break

        # If we can't find by order_id (sometimes payment event doesn't include it),
        # just update the most recent Square tx as a fallback.
        if not target:
            for t in reversed(transactions):
                if t.get("merchant") == "square":
                    target = t
                    break

        if target:
            target["items"] = items
            if total > 0:
                target["total"] = total
            target["currency"] = currency
            target["meta"] = target.get("meta") or {}
            target["meta"].update(
                {
                    "square_event_type": event_type,
                    "square_event_id": event_id,
                    "square_order_id": order_id,
                    "square_order": order,  # full raw order payload
                }
            )

        return {"ok": True, "enriched": True}

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

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
import sqlite3
from typing import List, Optional, Dict
from urllib.parse import urlencode

app = FastAPI(title="Receipts Ingestion API (Stripe + Square)")

# -------------------------
# In-memory state (temporary)
# -------------------------
transactions: List[dict] = []
processed_square_event_ids = set()
# -------------------------
# SQLite (demo spreadsheet)
# -------------------------
DB_PATH = os.getenv("DB_PATH") or "receipts.db"

def _db_conn():
    return sqlite3.connect(DB_PATH, check_same_thread=False)

def _db_init():
    conn = _db_conn()
    conn.execute("""
    CREATE TABLE IF NOT EXISTS receipt_items (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      merchant TEXT,
      payment_id TEXT,
      order_id TEXT,
      sku TEXT,
      item_name TEXT,
      quantity REAL,
      unit_price REAL,
      currency TEXT,
      total REAL,
      ts INTEGER
    )
    """)
    conn.commit()
    conn.close()

_db_init()
def _db_write_tx(tx: dict):
    """Upsert receipt line items into SQLite (demo-friendly, spreadsheet-like)."""
    if not isinstance(tx, dict):
        return

    user_id = tx.get("user_id") or "demo_user"
    merchant = tx.get("merchant") or ""
    payment_id = tx.get("payment_id") or ""
    currency = tx.get("currency") or ""
    total = tx.get("total") or 0
    ts = tx.get("timestamp") or int(time.time())

    meta = tx.get("meta") or {}
    order_id = meta.get("square_order_id") or meta.get("order_id") or ""

    items = tx.get("items") or []
    if not isinstance(items, list):
        items = []

    # If there are no items, still store a "header-ish" row so you can see the receipt exists.
    # (We'll overwrite it later once items arrive.)
    if not items:
        items = [{"sku": None, "name": "(no items yet)", "quantity": 0, "unit_price": 0}]

    conn = _db_conn()
    cur = conn.cursor()

    # delete old rows for this payment so the table stays clean on updates
    cur.execute(
        "DELETE FROM receipt_items WHERE user_id=? AND merchant=? AND payment_id=?",
        (user_id, merchant, payment_id),
    )

    for i in items:
        sku = (i or {}).get("sku")
        name = (i or {}).get("name") or ""
        qty = (i or {}).get("quantity") or 0
        unit_price = (i or {}).get("unit_price") or 0

        row_id = str(uuid.uuid4())
        cur.execute(
            """
            INSERT INTO receipt_items
            (id, user_id, merchant, payment_id, order_id, sku, item_name, quantity, unit_price, currency, total, ts)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (row_id, user_id, merchant, payment_id, order_id, sku, name, float(qty), float(unit_price), currency, float(total), int(ts)),
        )

    conn.commit()
    conn.close()

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

from fastapi.responses import RedirectResponse
import urllib.parse
import os

@app.get("/api/quickbooks/connect")
def quickbooks_connect():
    params = {
        "client_id": os.getenv("QBO_CLIENT_ID"),
        "redirect_uri": os.getenv("QBO_REDIRECT_URI"),
        "response_type": "code",
        "scope": "com.intuit.quickbooks.accounting",
        "state": "demo_user",
    }

    base_url = "https://appcenter.intuit.com/connect/oauth2"
    url = f"{base_url}?{urllib.parse.urlencode(params)}"
    return RedirectResponse(url)

@app.get("/api/quickbooks/callback")
async def quickbooks_callback(code: str, realmId: str):
    return {
        "ok": True,
        "code": code,
        "realm_id": realmId
    }

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
            _db_write_tx(existing)
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
        _db_write_tx(tx)
        return {"ok": True, "created": True}


    return {"ok": True, "ignored": True}

from fastapi.responses import HTMLResponse

@app.get("/demo/receipts", response_class=HTMLResponse)
async def demo_receipts(user_id: str = "demo_user", limit: int = 200):
    """
    Simple demo UI: renders receipt_items as an HTML table (spreadsheet vibe).
    """
    conn = _db_conn()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
          ts, merchant, payment_id, order_id, item_name, sku, quantity, unit_price, currency, total
        FROM receipt_items
        WHERE user_id=?
        ORDER BY ts DESC
        LIMIT ?
        """,
        (user_id, int(limit)),
    )
    rows = cur.fetchall()
    conn.close()

    def esc(s):
        s = "" if s is None else str(s)
        return (
            s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;")
        )

    html = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Receipts Demo</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial; padding:16px; background:#0b0b0d; color:#f3f4f6;}
    .wrap{max-width:1200px; margin:0 auto;}
    h1{margin:0 0 8px 0; font-size:18px;}
    .sub{opacity:.8; margin-bottom:12px; font-size:13px;}
    table{width:100%; border-collapse:collapse; background:#111114; border:1px solid #222; border-radius:10px; overflow:hidden;}
    th,td{padding:10px 8px; border-bottom:1px solid #1f1f24; font-size:12px; vertical-align:top;}
    th{position:sticky; top:0; background:#14141a; text-align:left; font-weight:600;}
    tr:hover td{background:#12121a;}
    .pill{display:inline-block; padding:2px 8px; border:1px solid #2b2b35; border-radius:999px; font-size:11px; opacity:.9;}
    .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;}
    .right{text-align:right;}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Receipts (demo table)</h1>
    <div class="sub">URL params: <span class="mono">?user_id=demo_user&limit=200</span></div>
    <table>
      <thead>
        <tr>
          <th>ts</th>
          <th>merchant</th>
          <th>payment_id</th>
          <th>order_id</th>
          <th>item</th>
          <th>sku</th>
          <th class="right">qty</th>
          <th class="right">unit</th>
          <th>currency</th>
          <th class="right">total</th>
        </tr>
      </thead>
      <tbody>
"""
    for r in rows:
        ts, merchant, payment_id, order_id, item_name, sku, qty, unit_price, currency, total = r
        html += "<tr>"
        html += f"<td class='mono'>{esc(ts)}</td>"
        html += f"<td><span class='pill'>{esc(merchant)}</span></td>"
        html += f"<td class='mono'>{esc(payment_id)}</td>"
        html += f"<td class='mono'>{esc(order_id)}</td>"
        html += f"<td>{esc(item_name)}</td>"
        html += f"<td class='mono'>{esc(sku)}</td>"
        html += f"<td class='right'>{esc(qty)}</td>"
        html += f"<td class='right'>{esc(unit_price)}</td>"
        html += f"<td class='mono'>{esc(currency)}</td>"
        html += f"<td class='right'>{esc(total)}</td>"
        html += "</tr>"

    html += """
      </tbody>
    </table>
  </div>
</body>
</html>
"""
    return HTMLResponse(html)


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


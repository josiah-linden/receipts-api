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
import requests
from requests.auth import HTTPBasicAuth
from datetime import datetime

app = FastAPI(title="Receipts Ingestion API (Stripe + Square)")

# -------------------------
# In-memory state (temporary)
# -------------------------
transactions: List[dict] = []
processed_square_event_ids = set()
qbo_tokens: Dict[str, dict] = {}
square_oauth_tokens: Dict[str, dict] = {}
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
      item TEXT,
      item_name TEXT,
      quantity REAL,
      unit_price REAL,
      currency TEXT,
      total REAL,
      ts INTEGER
    )
    """)
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(receipt_items)")
    cols = {row[1] for row in cur.fetchall()}
    if "item" not in cols:
        conn.execute("ALTER TABLE receipt_items ADD COLUMN item TEXT")
        conn.execute("UPDATE receipt_items SET item = item_name WHERE item IS NULL")
    conn.execute("""
    CREATE TABLE IF NOT EXISTS qbo_tokens (
      realm_id TEXT PRIMARY KEY,
      access_token TEXT,
      refresh_token TEXT,
      expires_at INTEGER,
      raw_json TEXT
    )
    """)
    conn.execute("""
    CREATE TABLE IF NOT EXISTS square_tokens (
      merchant_id TEXT PRIMARY KEY,
      access_token TEXT,
      refresh_token TEXT,
      expires_at INTEGER,
      raw_json TEXT
    )
    """)
    conn.commit()
    conn.close()

_db_init()
def _db_save_qbo_token(realm_id: str, tok: dict) -> None:
    if not realm_id or not isinstance(tok, dict):
        return

    expires_at = tok.get("expires_at")
    expires_in = tok.get("expires_in")
    if expires_at is None and expires_in:
        try:
            expires_at = int(time.time()) + int(expires_in)
        except (TypeError, ValueError):
            expires_at = None

    tok = dict(tok)
    if expires_at is not None:
        tok["expires_at"] = expires_at

    conn = _db_conn()
    conn.execute(
        """
        INSERT INTO qbo_tokens (realm_id, access_token, refresh_token, expires_at, raw_json)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(realm_id) DO UPDATE SET
          access_token=excluded.access_token,
          refresh_token=excluded.refresh_token,
          expires_at=excluded.expires_at,
          raw_json=excluded.raw_json
        """,
        (
            str(realm_id),
            tok.get("access_token"),
            tok.get("refresh_token"),
            expires_at,
            json.dumps(tok),
        ),
    )
    conn.commit()
    conn.close()

def _db_load_qbo_tokens() -> None:
    global qbo_tokens
    conn = _db_conn()
    cur = conn.cursor()
    cur.execute("SELECT realm_id, access_token, refresh_token, expires_at, raw_json FROM qbo_tokens")
    rows = cur.fetchall()
    conn.close()

    loaded: Dict[str, dict] = {}
    for realm_id, access_token, refresh_token, expires_at, raw_json in rows:
        tok: Dict[str, object]
        if raw_json:
            try:
                tok = json.loads(raw_json)
            except json.JSONDecodeError:
                tok = {}
        else:
            tok = {}
        if access_token:
            tok["access_token"] = access_token
        if refresh_token:
            tok["refresh_token"] = refresh_token
        if expires_at is not None:
            tok["expires_at"] = expires_at
        loaded[str(realm_id)] = tok

    qbo_tokens = loaded

_db_load_qbo_tokens()

def _db_save_square_token(merchant_id: str, tok: dict) -> None:
    if not merchant_id or not isinstance(tok, dict):
        return

    expires_at = tok.get("expires_at")
    expires_in = tok.get("expires_in")
    if expires_at is None and expires_in:
        try:
            expires_at = int(time.time()) + int(expires_in)
        except (TypeError, ValueError):
            expires_at = None

    tok = dict(tok)
    if expires_at is not None:
        tok["expires_at"] = expires_at

    conn = _db_conn()
    conn.execute(
        """
        INSERT INTO square_tokens (merchant_id, access_token, refresh_token, expires_at, raw_json)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(merchant_id) DO UPDATE SET
          access_token=excluded.access_token,
          refresh_token=excluded.refresh_token,
          expires_at=excluded.expires_at,
          raw_json=excluded.raw_json
        """,
        (
            str(merchant_id),
            tok.get("access_token"),
            tok.get("refresh_token"),
            expires_at,
            json.dumps(tok),
        ),
    )
    conn.commit()
    conn.close()

def _db_load_square_tokens() -> None:
    global square_oauth_tokens
    conn = _db_conn()
    cur = conn.cursor()
    cur.execute("SELECT merchant_id, access_token, refresh_token, expires_at, raw_json FROM square_tokens")
    rows = cur.fetchall()
    conn.close()

    loaded: Dict[str, dict] = {}
    for merchant_id, access_token, refresh_token, expires_at, raw_json in rows:
        tok: Dict[str, object]
        if raw_json:
            try:
                tok = json.loads(raw_json)
            except json.JSONDecodeError:
                tok = {}
        else:
            tok = {}
        if access_token:
            tok["access_token"] = access_token
        if refresh_token:
            tok["refresh_token"] = refresh_token
        if expires_at is not None:
            tok["expires_at"] = expires_at
        loaded[str(merchant_id)] = tok

    square_oauth_tokens = loaded

_db_load_square_tokens()
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

    # If there are no items, store a single summary line so receipts are still visible.
    # (We'll overwrite it later once items arrive.)
    if not items:
        items = [{"sku": None, "name": "Receipt total", "quantity": 1, "unit_price": float(total)}]

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
            (id, user_id, merchant, payment_id, order_id, sku, item, item_name, quantity, unit_price, currency, total, ts)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (row_id, user_id, merchant, payment_id, order_id, sku, name, name, float(qty), float(unit_price), currency, float(total), int(ts)),
        )

    conn.commit()
    conn.close()

def _db_load_square_tx_by_order_id(order_id: str) -> Optional[dict]:
    if not order_id:
        return None
    conn = _db_conn()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT user_id, payment_id, currency, total, ts
        FROM receipt_items
        WHERE merchant = 'square' AND order_id = ?
        ORDER BY ts DESC
        LIMIT 1
        """,
        (order_id,),
    )
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    user_id, payment_id, currency, total, ts = row
    return {
        "id": str(uuid.uuid4()),
        "user_id": user_id or "demo_user",
        "merchant": "square",
        "payment_id": payment_id or "",
        "timestamp": ts or int(time.time()),
        "currency": currency or "",
        "total": total or 0,
        "items": [],
        "meta": {
            "square_order_id": order_id,
        },
    }

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

def _square_resolve_catalog_fields(catalog_object_id: Optional[str]) -> Dict[str, Optional[str]]:
    if not catalog_object_id:
        return {"name": None, "sku": None}

    obj = _square_get_catalog_object(catalog_object_id)
    if not isinstance(obj, dict):
        return {"name": None, "sku": None}

    obj_type = obj.get("type")
    if obj_type == "ITEM":
        item_data = obj.get("item_data") or {}
        return {"name": item_data.get("name"), "sku": None}

    if obj_type == "ITEM_VARIATION":
        variation_data = obj.get("item_variation_data") or {}
        name = variation_data.get("name")
        sku = variation_data.get("sku")
        item_id = variation_data.get("item_id")
        if item_id:
            item_obj = _square_get_catalog_object(item_id)
            if isinstance(item_obj, dict):
                item_data = item_obj.get("item_data") or {}
                item_name = item_data.get("name")
                if item_name and name:
                    name = f"{item_name} - {name}"
                elif item_name:
                    name = item_name
        return {"name": name, "sku": sku}

    return {"name": None, "sku": None}

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
            if catalog_object_id and (not sku or not name):
                resolved = _square_resolve_catalog_fields(catalog_object_id)
                sku = sku or resolved.get("sku")
                name = name or (resolved.get("name") or "")

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
                if catalog_object_id and (not sku or not name):
                    resolved = _square_resolve_catalog_fields(catalog_object_id)
                    sku = sku or resolved.get("sku")
                    name = name or (resolved.get("name") or "")

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
    _db_save_square_token(merchant_id, data)

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
    return _qbo_exchange_and_store(code, realmId)

# -------------------------
# QuickBooks: read CompanyInfo (sanity check)
# -------------------------
QBO_ENV = os.getenv("QBO_ENV", "sandbox").lower()  # "sandbox" or "production"

QBO_BASE = (
    "https://sandbox-quickbooks.api.intuit.com"
    if QBO_ENV != "production"
    else "https://quickbooks.api.intuit.com"
)
QBO_CLIENT_ID = os.getenv("QBO_CLIENT_ID")
QBO_CLIENT_SECRET = os.getenv("QBO_CLIENT_SECRET")
QBO_REDIRECT_URI = os.getenv("QBO_REDIRECT_URI")

def _qbo_request(realm_id: str, path: str, access_token: str) -> dict:
    url = f"{QBO_BASE}{path}"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read().decode("utf-8") or "{}"
            return json.loads(raw)
    except urllib.error.HTTPError as e:
        try:
            err = e.read().decode("utf-8")
        except Exception:
            err = str(e)
        return {"error": True, "status": e.code, "detail": err}
    except Exception as e:
        return {"error": True, "detail": str(e)}
def _qbo_post(realm_id: str, path: str, access_token: str, payload: dict) -> dict:
    url = f"{QBO_BASE}{path}"
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read().decode("utf-8") or "{}"
            return json.loads(raw)
    except urllib.error.HTTPError as e:
        try:
            err = e.read().decode("utf-8")
        except Exception:
            err = str(e)
        return {"error": True, "status": e.code, "detail": err}
    except Exception as e:
        return {"error": True, "detail": str(e)}

def _qbo_query(realm_id: str, query: str, access_token: str) -> dict:
    url = f"{QBO_BASE}/v3/company/{realm_id}/query?minorversion=65"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
        "Content-Type": "application/text",
    }
    req = urllib.request.Request(url, data=query.encode("utf-8"), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read().decode("utf-8") or "{}"
            return json.loads(raw)
    except urllib.error.HTTPError as e:
        try:
            err = e.read().decode("utf-8")
        except Exception:
            err = str(e)
        return {"error": True, "status": e.code, "detail": err}
    except Exception as e:
        return {"error": True, "detail": str(e)}

def _qbo_refresh_access_token(realm_id: str, refresh_token: str) -> dict:
    if not refresh_token:
        return {"error": True, "detail": "Missing refresh token"}

    token_url = f"{_qbo_base_url()}/oauth2/v1/tokens/bearer"
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    }

    r = requests.post(
        token_url,
        data=data,
        headers={"Accept": "application/json"},
        auth=HTTPBasicAuth(QBO_CLIENT_ID, QBO_CLIENT_SECRET),
        timeout=20,
    )

    if r.status_code >= 400:
        return {"error": True, "status": r.status_code, "detail": r.text}

    tok = r.json()
    expires_in = tok.get("expires_in")
    if expires_in:
        try:
            tok["expires_at"] = int(time.time()) + int(expires_in)
        except (TypeError, ValueError):
            pass

    existing = qbo_tokens.get(str(realm_id)) or {}
    merged = {**existing, **tok}
    qbo_tokens[str(realm_id)] = merged
    _db_save_qbo_token(str(realm_id), merged)
    return merged

def _qbo_get_valid_access_token(realm_id: str) -> str:
    tok = qbo_tokens.get(str(realm_id)) or {}
    access_token = tok.get("access_token")
    refresh_token = tok.get("refresh_token")
    expires_at = tok.get("expires_at")

    if refresh_token and (not access_token or (expires_at and time.time() >= int(expires_at) - 60)):
        refreshed = _qbo_refresh_access_token(realm_id, refresh_token)
        if not refreshed.get("error"):
            return refreshed.get("access_token") or ""
    return access_token or ""

def _qbo_query_with_refresh(realm_id: str, query: str, access_token: str) -> dict:
    data = _qbo_query(realm_id, query, access_token)
    if data.get("status") == 401:
        refresh_token = (qbo_tokens.get(str(realm_id)) or {}).get("refresh_token")
        if refresh_token:
            refreshed = _qbo_refresh_access_token(realm_id, refresh_token)
            new_access_token = refreshed.get("access_token")
            if new_access_token:
                return _qbo_query(realm_id, query, new_access_token)
    return data

def _qbo_get_first_item_id(access_token: str, realm_id: str) -> Optional[str]:
    data = _qbo_query_with_refresh(realm_id, "SELECT Id, Name FROM Item MAXRESULTS 1", access_token)
    items = (data.get("QueryResponse") or {}).get("Item") or []
    if items:
        return items[0].get("Id")
    return None

def maybe_autopost_to_qbo_from_tx(tx: dict):
    if not qbo_tokens or not tx.get("items"):
        return

    realm_id = list(qbo_tokens.keys())[0]
    access_token = _qbo_get_valid_access_token(realm_id)
    if not access_token:
        print("QBO access token missing; reconnect required.")
        return
    try:
        item_id = _qbo_get_or_create_demo_item_id(realm_id, access_token)
    except Exception as exc:
        print("QBO item lookup/create failed:", exc)
        return

    lines = []
    for item in tx["items"]:
        qty = item.get("quantity") or 0
        unit_price = item.get("unit_price") or 0
        lines.append({
            "DetailType": "SalesItemLineDetail",
            "Amount": unit_price * qty,
            "Description": item.get("name") or "",
            "SalesItemLineDetail": {
                "Qty": qty,
                "UnitPrice": unit_price,
                "ItemRef": {"value": item_id},
            },
        })

    payload = {
        "Line": lines,
        "TotalAmt": tx["total"],
    }

    resp = _qbo_post(
        realm_id,
        f"/v3/company/{realm_id}/salesreceipt?minorversion=65",
        access_token,
        payload,
    )
    print("QBO salesreceipt resp:", resp)

@app.get("/api/quickbooks/companyinfo")
async def quickbooks_companyinfo(realm_id: str):
    # Requires that quickbooks_callback stored tokens somewhere like:
    # qbo_tokens[realm_id] = {"access_token": "...", ...}
    try:
        global qbo_tokens
    except NameError:
        qbo_tokens = {}

    tok = qbo_tokens.get(realm_id) or {}
    access_token = tok.get("access_token")
    if not access_token:
        raise HTTPException(status_code=401, detail="No QuickBooks token for this realm_id. Reconnect QuickBooks.")

    # CompanyInfo endpoint expects both company_id and companyinfo_id = realm_id
    path = f"/v3/company/{realm_id}/companyinfo/{realm_id}?minorversion=65"
    data = _qbo_request(realm_id, path, access_token)

    # If token expired/revoked, you'll see 401 here
    if isinstance(data, dict) and data.get("status") == 401:
        raise HTTPException(status_code=401, detail="QuickBooks token expired. Reconnect QuickBooks.")

    return data

# -------------------------
# QuickBooks: minimal POST helpers (SalesReceipt)
# -------------------------
def _qbo_post_json(realm_id: str, path: str, access_token: str, payload: dict) -> dict:
    url = f"{QBO_BASE}{path}"
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read().decode("utf-8") or "{}"
            return json.loads(raw)
    except urllib.error.HTTPError as e:
        try:
            err = e.read().decode("utf-8")
        except Exception:
            err = str(e)
        return {"error": True, "status": e.code, "detail": err}
    except Exception as e:
        return {"error": True, "detail": str(e)}

def _qbo_get_or_create_demo_item_id(realm_id: str, access_token: str) -> str:
    # 1) find existing “Receipt Item”
    data = _qbo_query_with_refresh(realm_id, "SELECT Id, Name FROM Item WHERE Name = 'Receipt Item' MAXRESULTS 1", access_token)
    if data.get("error"):
        raise RuntimeError(f"QBO query failed: {data}")
    items = (data.get("QueryResponse") or {}).get("Item") or []
    if items:
        return items[0]["Id"]

    # 2) find ANY Income account to attach item to
    acct = _qbo_query_with_refresh(realm_id, "SELECT Id, Name FROM Account WHERE AccountType = 'Income' MAXRESULTS 1", access_token)
    if acct.get("error"):
        raise RuntimeError(f"QBO account lookup failed: {acct}")
    accts = (acct.get("QueryResponse") or {}).get("Account") or []
    if not accts:
        raise Exception("No Income account found in QBO (sandbox). Create one Income account first.")
    income_acct_id = accts[0]["Id"]

    # 3) create the item
    payload = {
        "Name": "Receipt Item",
        "Type": "Service",
        "IncomeAccountRef": {"value": income_acct_id},
    }
    created = _qbo_post_json(realm_id, f"/v3/company/{realm_id}/item?minorversion=65", access_token, payload)
    if created.get("error"):
        raise Exception(f"QBO item create failed: {created}")
    return created["Item"]["Id"]

def qbo_push_tx(tx: dict) -> dict:
    if not tx or not tx.get("items"):
        return {"ok": False, "detail": "No items"}

    if not qbo_tokens:
        return {"ok": False, "detail": "No QBO tokens in memory (run connect+exchange)"}

    realm_id = list(qbo_tokens.keys())[0]
    access_token = _qbo_get_valid_access_token(realm_id)
    if not access_token:
        return {"ok": False, "detail": "Missing access_token (run exchange)"}

    try:
        item_id = _qbo_get_or_create_demo_item_id(realm_id, access_token)
    except Exception as exc:
        detail = str(exc) or "QBO item lookup/create failed"
        return {"ok": False, "detail": detail}

    lines = []
    for it in tx["items"]:
        qty = float(it.get("quantity") or 1)
        unit = float(it.get("unit_price") or 0)
        lines.append({
            "DetailType": "SalesItemLineDetail",
            "Amount": round(qty * unit, 2),
            "SalesItemLineDetail": {
                "Qty": qty,
                "UnitPrice": unit,
                "ItemRef": {"value": item_id}
            },
            "Description": it.get("name") or "",
        })

    payload = {
        "Line": lines,
        "TotalAmt": float(tx.get("total") or 0),
        "PrivateNote": f"{tx.get('merchant')} payment_id={tx.get('payment_id')}",
    }

    response = _qbo_post_json(realm_id, f"/v3/company/{realm_id}/salesreceipt?minorversion=65", access_token, payload)
    if response.get("status") == 401:
        refreshed_access = _qbo_get_valid_access_token(realm_id)
        if refreshed_access and refreshed_access != access_token:
            response = _qbo_post_json(
                realm_id,
                f"/v3/company/{realm_id}/salesreceipt?minorversion=65",
                refreshed_access,
                payload,
            )
    return response

def _register_qbo_push_demo_routes() -> None:
    qbo_push_path = os.path.join(os.path.dirname(__file__), "qbo_push.py")
    if not os.path.isfile(qbo_push_path):
        return

    import importlib.util

    spec = importlib.util.spec_from_file_location("qbo_push", qbo_push_path)
    if not spec or not spec.loader:
        return

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    register_routes = getattr(module, "register_routes", None)
    if callable(register_routes):
        register_routes(app, _db_load_qbo_tokens, lambda: qbo_tokens, qbo_push_tx)

_register_qbo_push_demo_routes()

from meta_audience import register_routes as register_meta_audience_routes

register_meta_audience_routes(app, DB_PATH)

@app.get("/api/quickbooks/status")
async def quickbooks_status():
    realm_id = list(qbo_tokens.keys())[0] if qbo_tokens else None
    has_token = bool(realm_id and (qbo_tokens.get(realm_id) or {}).get("access_token"))
    return {"ok": True, "realm_id": realm_id, "has_token": has_token}


def _qbo_base_url() -> str:
    return "https://oauth.platform.intuit.com"  # token endpoint is same for sandbox/prod

def _qbo_exchange_and_store(code: str, realm_id: str) -> dict:
    if not QBO_CLIENT_ID or not QBO_CLIENT_SECRET or not QBO_REDIRECT_URI:
        raise HTTPException(status_code=500, detail="Missing QBO env vars")

    token_url = f"{_qbo_base_url()}/oauth2/v1/tokens/bearer"

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": QBO_REDIRECT_URI,
    }

    r = requests.post(
        token_url,
        data=data,
        headers={"Accept": "application/json"},
        auth=HTTPBasicAuth(QBO_CLIENT_ID, QBO_CLIENT_SECRET),
        timeout=20,
    )

    if r.status_code >= 400:
        return {"ok": False, "status": r.status_code, "detail": r.text}

    tok = r.json()
    expires_in = tok.get("expires_in")
    if expires_in:
        try:
            tok["expires_at"] = int(time.time()) + int(expires_in)
        except (TypeError, ValueError):
            pass
    qbo_tokens[str(realm_id)] = tok
    _db_save_qbo_token(realm_id, tok)
    return {"ok": True, "realm_id": realm_id}

@app.get("/api/quickbooks/exchange")
async def quickbooks_exchange(code: str, realmId: str):
    return _qbo_exchange_and_store(code, realmId)

def _qbo_get_or_create_item(access_token: str, realm_id: str) -> str:
    url = f"{_qbo_base_url()}/v3/company/{realm_id}/query"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
        "Content-Type": "application/text",
    }

    # 1) Try to find existing demo item
    query = "select * from Item where Name = 'Receipt Item'"
    req = urllib.request.Request(url, data=query.encode(), headers=headers, method="POST")
    with urllib.request.urlopen(req) as r:
        data = json.loads(r.read().decode())
        items = data.get("QueryResponse", {}).get("Item", [])
        if items:
            return items[0]["Id"]

    # 2) Create it if missing
    create_url = f"{_qbo_base_url()}/v3/company/{realm_id}/item"
    payload = {
        "Name": "Receipt Item",
        "Type": "NonInventory",
        "IncomeAccountRef": {"value": qbo_item_id}
    }

    req = urllib.request.Request(
        create_url,
        data=json.dumps(payload).encode(),
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read().decode())["Item"]["Id"]


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
            order = obj.get("order_updated")
        if not isinstance(order, dict):
            return {"ok": True, "ignored": True}

        order_id = order.get("id") or order.get("order_id")
        if not order_id:
            return {"ok": True, "ignored": True}

        items: List[dict] = []
        order_full = None
        order_keys = set(order.keys())
        minimal_order_payload = order_keys.issubset({"id", "order_id"})
        if isinstance(order, dict) and not minimal_order_payload:
            order_full = order
            items = _order_to_items(order)

        if SQUARE_ACCESS_TOKEN:
            fetched_order = _square_get_order(order_id)
            if isinstance(fetched_order, dict):
                order_full = fetched_order
                fetched_items = _order_to_items(fetched_order)
                if fetched_items:
                    items = fetched_items

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
                _db_write_tx(t)
                return {"ok": True, "updated_existing": True}

        if order_full is not None:
            db_tx = _db_load_square_tx_by_order_id(order_id)
            if db_tx:
                if items:
                    db_tx["items"] = items
                db_tx_meta = db_tx.get("meta") or {}
                db_tx_meta["square_order"] = order_full
                db_tx_meta["square_event_type"] = event_type
                db_tx_meta["square_event_id"] = event_id
                db_tx["meta"] = db_tx_meta
                _db_write_tx(db_tx)
                return {"ok": True, "updated_existing_db": True}

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
        maybe_autopost_to_qbo_from_tx(tx)
        return {"ok": True, "created": True}


    return {"ok": True, "ignored": True}

from fastapi.responses import HTMLResponse

@app.get("/demo/receipts", response_class=HTMLResponse)
async def demo_receipts(
    user_id: str = "demo_user",
    limit: int = 200,
    merchant: Optional[str] = None,
    payment_id: Optional[str] = None,
    order_id: Optional[str] = None,
    item: Optional[str] = None,
    sku: Optional[str] = None,
    start_ts: Optional[str] = None,
    end_ts: Optional[str] = None,
    min_total: Optional[str] = None,
    max_total: Optional[str] = None,
):
    """
    Simple demo UI: shows receipts with filters and grouped line items.
    """
    where = ["user_id = ?"]
    params: List[object] = [user_id]

    def parse_datetime_value(raw: Optional[str]) -> Optional[int]:
        if raw is None:
            return None
        raw = str(raw).strip()
        if not raw:
            return None
        try:
            return int(raw)
        except ValueError:
            try:
                parsed = datetime.fromisoformat(raw)
            except ValueError:
                return None
            return int(parsed.timestamp())

    def parse_float_value(raw: Optional[str]) -> Optional[float]:
        if raw is None:
            return None
        raw = str(raw).strip()
        if not raw:
            return None
        try:
            return float(raw)
        except ValueError:
            return None

    parsed_start_ts = parse_datetime_value(start_ts)
    parsed_end_ts = parse_datetime_value(end_ts)
    parsed_min_total = parse_float_value(min_total)
    parsed_max_total = parse_float_value(max_total)

    if merchant:
        where.append("merchant = ?")
        params.append(merchant)
    if payment_id:
        where.append("payment_id LIKE ?")
        params.append(f"%{payment_id}%")
    if order_id:
        where.append("order_id LIKE ?")
        params.append(f"%{order_id}%")
    if item:
        where.append("COALESCE(item, item_name) LIKE ?")
        params.append(f"%{item}%")
    if sku:
        where.append("sku LIKE ?")
        params.append(f"%{sku}%")
    if parsed_start_ts is not None:
        where.append("ts >= ?")
        params.append(int(parsed_start_ts))
    if parsed_end_ts is not None:
        where.append("ts <= ?")
        params.append(int(parsed_end_ts))
    if parsed_min_total is not None:
        where.append("total >= ?")
        params.append(float(parsed_min_total))
    if parsed_max_total is not None:
        where.append("total <= ?")
        params.append(float(parsed_max_total))

    where_clause = " AND ".join(where) if where else "1=1"

    conn = _db_conn()
    cur = conn.cursor()
    cur.execute(
        f"""
        SELECT
          ts, merchant, payment_id, order_id, COALESCE(item, item_name) as item_name, sku, quantity, unit_price, currency, total
        FROM receipt_items
        WHERE {where_clause}
        ORDER BY ts DESC
        LIMIT ?
        """,
        (*params, int(limit)),
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

    def format_ts(ts_value: Optional[int]) -> str:
        if not ts_value:
            return ""
        return datetime.fromtimestamp(int(ts_value)).strftime("%Y-%m-%d %H:%M:%S")

    def format_money(amount: Optional[float]) -> str:
        try:
            return f"{float(amount):,.2f}"
        except (TypeError, ValueError):
            return "0.00"

    grouped: Dict[tuple, List[dict]] = {}
    for r in rows:
        ts, merchant_val, payment_val, order_val, item_name, sku_val, qty, unit_price, currency, total = r
        key = (ts, merchant_val, payment_val, order_val, currency, total)
        grouped.setdefault(key, []).append(
            {
                "item_name": item_name,
                "sku": sku_val,
                "quantity": qty,
                "unit_price": unit_price,
            }
        )

    if SQUARE_ACCESS_TOKEN:
        for key, items in list(grouped.items()):
            ts, merchant_val, payment_val, order_val, currency, total = key
            if merchant_val != "square" or not order_val:
                continue
            if not (len(items) == 1 and items[0].get("item_name") == "Receipt total"):
                continue
            order_full = _square_get_order(order_val)
            if not isinstance(order_full, dict):
                continue
            refreshed_items = _order_to_items(order_full)
            if not refreshed_items:
                continue
            tx = {
                "id": str(uuid.uuid4()),
                "user_id": user_id,
                "merchant": "square",
                "payment_id": payment_val or "",
                "timestamp": ts or int(time.time()),
                "currency": currency or "",
                "total": total or 0,
                "items": refreshed_items,
                "meta": {
                    "square_order_id": order_val,
                    "square_order": order_full,
                    "square_event_type": "demo_refresh",
                },
            }
            _db_write_tx(tx)
            grouped[key] = [
                {
                    "item_name": it.get("name") or "",
                    "sku": it.get("sku"),
                    "quantity": it.get("quantity") or 0,
                    "unit_price": it.get("unit_price") or 0,
                }
                for it in refreshed_items
            ]

    html = f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Receipts</title>
  <style>
    body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial; padding:16px; background:#0b0b0d; color:#f3f4f6;}}
    .wrap{{max-width:1200px; margin:0 auto;}}
    h1{{margin:0 0 6px 0; font-size:20px;}}
    .sub{{opacity:.75; margin-bottom:16px; font-size:13px;}}
    .panel{{background:#111114; border:1px solid #222; border-radius:12px; padding:16px; margin-bottom:16px;}}
    .grid{{display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px;}}
    label{{display:block; font-size:12px; opacity:.75; margin-bottom:6px;}}
    input,select{{width:100%; background:#0c0c11; border:1px solid #23232a; border-radius:8px; color:#f3f4f6; padding:8px 10px; font-size:12px;}}
    button{{background:#2563eb; border:none; border-radius:8px; color:white; padding:10px 14px; font-size:13px; font-weight:600; cursor:pointer;}}
    .pill{{display:inline-block; padding:2px 8px; border:1px solid #2b2b35; border-radius:999px; font-size:11px; opacity:.9;}}
    .mono{{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;}}
    .cards{{display:flex; flex-direction:column; gap:12px;}}
    .card{{background:#111114; border:1px solid #222; border-radius:12px; padding:14px;}}
    .row{{display:flex; flex-wrap:wrap; gap:8px 16px; align-items:center;}}
    .meta{{font-size:12px; opacity:.8;}}
    .items{{margin-top:10px; border-top:1px dashed #1f1f24; padding-top:10px;}}
    .item{{display:flex; justify-content:space-between; font-size:12px; padding:4px 0;}}
    .item-name{{display:flex; flex-direction:column;}}
    .sku{{opacity:.65; font-size:11px;}}
    .item-meta{{text-align:right;}}
    .line-total{{opacity:.75; font-size:11px;}}
    .total-row{{display:flex; justify-content:space-between; margin-top:10px; padding-top:10px; border-top:1px solid #1f1f24; font-weight:600;}}
    .right{{text-align:right;}}
    .empty{{padding:24px; text-align:center; opacity:.75;}}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Receipts</h1>
    <div class="sub">Filter and search stored receipts. Results are pulled from the permanent database.</div>
    <form class="panel" method="get">
      <div class="grid">
        <div>
          <label>User ID</label>
          <input name="user_id" value="{esc(user_id)}" />
        </div>
        <div>
          <label>Merchant</label>
          <input name="merchant" value="{esc(merchant)}" placeholder="square" />
        </div>
        <div>
          <label>Payment ID</label>
          <input name="payment_id" value="{esc(payment_id)}" placeholder="search" />
        </div>
        <div>
          <label>Order ID</label>
          <input name="order_id" value="{esc(order_id)}" placeholder="search" />
        </div>
        <div>
          <label>Item</label>
          <input name="item" value="{esc(item)}" placeholder="item name" />
        </div>
        <div>
          <label>SKU</label>
          <input name="sku" value="{esc(sku)}" placeholder="sku" />
        </div>
        <div>
          <label>Start date/time</label>
          <input type="datetime-local" name="start_ts" value="{esc(start_ts)}" />
        </div>
        <div>
          <label>End date/time</label>
          <input type="datetime-local" name="end_ts" value="{esc(end_ts)}" />
        </div>
        <div>
          <label>Min total</label>
          <input name="min_total" value="{esc(min_total)}" placeholder="0.00" />
        </div>
        <div>
          <label>Max total</label>
          <input name="max_total" value="{esc(max_total)}" placeholder="100.00" />
        </div>
        <div>
          <label>Limit</label>
          <input name="limit" value="{esc(limit)}" />
        </div>
        <div style="display:flex; align-items:end;">
          <button type="submit">Search receipts</button>
        </div>
      </div>
    </form>
    <div class="cards">
"""

    if not grouped:
        html += "<div class='panel empty'>No receipts found for this search.</div>"
    else:
        for key, items in grouped.items():
            ts, merchant_val, payment_val, order_val, currency, total = key
            html += "<div class='card'>"
            html += "<div class='row'>"
            html += f"<span class='pill'>{esc(merchant_val)}</span>"
            html += f"<span class='meta'>Date: <span class='mono'>{esc(format_ts(ts))}</span></span>"
            html += "</div>"
            html += "<div class='row meta' style='margin-top:6px;'>"
            html += f"<div>Payment ID: <span class='mono'>{esc(payment_val)}</span></div>"
            html += f"<div>Order ID: <span class='mono'>{esc(order_val)}</span></div>"
            html += "</div>"
            html += "<div class='items'>"
            line_items_total = 0.0
            for item_row in items:
                line_total = (item_row.get("quantity") or 0) * (item_row.get("unit_price") or 0)
                line_items_total += float(line_total or 0)
                html += "<div class='item'>"
                html += "<div class='item-name'>"
                html += f"<div>{esc(item_row['item_name'])}</div>"
                if item_row.get("sku"):
                    html += f"<div class='sku mono'>{esc(item_row['sku'])}</div>"
                html += "</div>"
                html += "<div class='item-meta'>"
                html += f"<div>{esc(item_row['quantity'])} × {esc(format_money(item_row['unit_price']))}</div>"
                html += f"<div class='line-total'>{esc(currency)} {esc(format_money(line_total))}</div>"
                html += "</div>"
                html += "</div>"
            diff_total = float(total or 0) - line_items_total
            if abs(diff_total) >= 0.01:
                html += "<div class='item'>"
                html += "<div class='item-name'>Other charges (tax/fees)</div>"
                html += "<div class='item-meta'>"
                html += f"<div class='line-total'>{esc(currency)} {esc(format_money(diff_total))}</div>"
                html += "</div>"
                html += "<div class='item-meta'>"
                html += f"<div>{esc(item_row['quantity'])} × {esc(format_money(item_row['unit_price']))}</div>"
                html += f"<div class='line-total'>{esc(currency)} {esc(format_money(line_total))}</div>"
                html += "</div>"
                html += "</div>"
            html += "</div>"
            html += "<div class='total-row'>"
            html += "<div>Total</div>"
            html += f"<div>{esc(currency)} {esc(format_money(total))}</div>"
            html += "</div>"
            html += "</div>"

    html += """
    </div>
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
            _db_write_tx(t)
            updated += 1

    if checked < limit:
        conn = _db_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT payment_id, order_id, currency, total, MAX(ts) as ts
            FROM receipt_items
            WHERE user_id = ? AND merchant = 'square'
            GROUP BY payment_id, order_id, currency, total
            ORDER BY ts DESC
            LIMIT ?
            """,
            (user_id, int(limit - checked)),
        )
        rows = cur.fetchall()
        conn.close()

        for payment_id, order_id, currency, total, ts in rows:
            if not order_id:
                continue
            order_full = _square_get_order(order_id)
            if not isinstance(order_full, dict):
                continue
            items = _order_to_items(order_full)
            if not items:
                continue
            tx = {
                "id": str(uuid.uuid4()),
                "user_id": user_id,
                "merchant": "square",
                "payment_id": payment_id or "",
                "timestamp": ts or int(time.time()),
                "currency": currency or "",
                "total": total or 0,
                "items": items,
                "meta": {
                    "square_order_id": order_id,
                    "square_order": order_full,
                    "square_event_type": "backfill_db",
                },
            }
            _db_write_tx(tx)
            updated += 1

    return {"ok": True, "checked": checked, "updated": updated}

@app.get("/")
async def root():
    return {"ok": True, "service": "receipts-ingestion"}

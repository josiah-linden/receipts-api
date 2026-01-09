import hashlib
import os
import sqlite3
import time
import uuid
from typing import List, Optional

import requests
from fastapi import HTTPException, FastAPI

META_GRAPH_BASE = os.getenv("META_GRAPH_BASE", "https://graph.facebook.com/v18.0")


def _meta_access_token() -> str:
    token = os.getenv("META_ACCESS_TOKEN")
    if not token:
        raise HTTPException(status_code=500, detail="META_ACCESS_TOKEN not set")
    return token


def _meta_ad_account_id() -> str:
    account_id = os.getenv("META_AD_ACCOUNT_ID")
    if not account_id:
        raise HTTPException(status_code=500, detail="META_AD_ACCOUNT_ID not set")
    return account_id


def _db_conn(db_path: str) -> sqlite3.Connection:
    return sqlite3.connect(db_path, check_same_thread=False)


def _hash_value(value: str) -> str:
    normalized = (value or "").strip().lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _select_user_ids(
    db_path: str,
    days_since_visit: Optional[int] = None,
    merchant: Optional[str] = None,
    item_contains: Optional[str] = None,
) -> List[str]:
    conn = _db_conn(db_path)
    cur = conn.cursor()

    where = []
    params: List[object] = []
    if merchant:
        where.append("merchant = ?")
        params.append(merchant)

    if item_contains:
        where.append("LOWER(COALESCE(item, item_name)) LIKE ?")
        params.append(f"%{item_contains.lower()}%")

    where_clause = f"WHERE {' AND '.join(where)}" if where else ""

    cutoff = None
    if days_since_visit is not None:
        cutoff = int(time.time()) - int(days_since_visit) * 24 * 60 * 60

    having_clause = ""
    if cutoff is not None:
        having_clause = "HAVING last_seen <= ?"
        params.append(int(cutoff))

    cur.execute(
        f"""
        SELECT
          user_id,
          MAX(ts) as last_seen
        FROM receipt_items
        {where_clause}
        GROUP BY user_id
        {having_clause}
        """
    ,
        params,
    )
    rows = cur.fetchall()
    conn.close()
    return [str(row[0]) for row in rows if row and row[0]]


def _create_custom_audience(
    access_token: str,
    ad_account_id: str,
    name: str,
    description: str,
) -> dict:
    url = f"{META_GRAPH_BASE}/act_{ad_account_id}/customaudiences"
    payload = {
        "name": name,
        "subtype": "CUSTOM",
        "description": description,
        "customer_file_source": "USER_PROVIDED_ONLY",
    }
    response = requests.post(url, params={"access_token": access_token}, json=payload, timeout=30)
    data = response.json()
    if response.status_code >= 400 or data.get("error"):
        raise HTTPException(status_code=502, detail={"meta_error": data})
    return data


def _add_users_to_custom_audience(
    access_token: str,
    audience_id: str,
    user_ids: List[str],
) -> dict:
    url = f"{META_GRAPH_BASE}/{audience_id}/users"
    hashed_ids = [[_hash_value(user_id)] for user_id in user_ids]
    payload = {
        "schema": ["EXTERN_ID"],
        "data": hashed_ids,
    }
    response = requests.post(url, params={"access_token": access_token}, json=payload, timeout=30)
    data = response.json()
    if response.status_code >= 400 or data.get("error"):
        raise HTTPException(status_code=502, detail={"meta_error": data})
    return data


def _seed_receipt_items(
    db_path: str,
    count: int,
    merchant: str,
    item: str,
    days_ago: int,
) -> int:
    conn = _db_conn(db_path)
    cur = conn.cursor()
    cur.execute(
        """
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
        """
    )
    ts = int(time.time()) - int(days_ago) * 24 * 60 * 60
    rows = []
    for idx in range(1, count + 1):
        rows.append(
            (
                str(uuid.uuid4()),
                f"demo_user_{idx}",
                merchant,
                f"pay_{idx}",
                f"order_{idx}",
                f"sku_{idx}",
                item,
                item.title(),
                1,
                5.50,
                "USD",
                5.50,
                ts,
            )
        )
    cur.executemany(
        """
        INSERT INTO receipt_items
          (id, user_id, merchant, payment_id, order_id, sku, item, item_name,
           quantity, unit_price, currency, total, ts)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    conn.commit()
    conn.close()
    return len(rows)


def register_routes(app: FastAPI, db_path: str) -> None:
    @app.post("/api/meta/audiences/custom")
    async def meta_custom_audience(
        audience_name: str,
        days_since_visit: Optional[int] = None,
        merchant: Optional[str] = None,
        item_contains: Optional[str] = None,
        description: Optional[str] = None,
    ):
        access_token = _meta_access_token()
        ad_account_id = _meta_ad_account_id()

        user_ids = _select_user_ids(
            db_path,
            days_since_visit=days_since_visit,
            merchant=merchant,
            item_contains=item_contains,
        )
        if not user_ids:
            return {"ok": True, "audience_created": False, "count": 0}

        desc = description or "Audience uploaded from receipts database."
        if merchant:
            desc = f"{desc} Merchant filter: {merchant}."
        if item_contains:
            desc = f"{desc} Item filter: {item_contains}."
        if days_since_visit is not None:
            desc = f"{desc} Days since visit: {days_since_visit}."

        audience = _create_custom_audience(
            access_token=access_token,
            ad_account_id=ad_account_id,
            name=audience_name,
            description=desc,
        )
        audience_id = audience.get("id")
        upload = _add_users_to_custom_audience(access_token, audience_id, user_ids)

        return {
            "ok": True,
            "audience_created": True,
            "audience_id": audience_id,
            "count": len(user_ids),
            "audience": audience,
            "upload": upload,
        }

    @app.post("/api/meta/audiences/seed")
    async def meta_seed_audience(
        count: int = 25,
        merchant: str = "square",
        item: str = "coffee",
        days_ago: int = 9,
    ):
        if os.getenv("ALLOW_TEST_SEED", "").lower() != "true":
            raise HTTPException(status_code=403, detail="Test seeding is disabled.")
        if count <= 0:
            raise HTTPException(status_code=400, detail="count must be positive.")
        if days_ago < 0:
            raise HTTPException(status_code=400, detail="days_ago must be >= 0.")
        inserted = _seed_receipt_items(
            db_path=db_path,
            count=count,
            merchant=merchant,
            item=item,
            days_ago=days_ago,
        )
        return {"ok": True, "inserted": inserted}

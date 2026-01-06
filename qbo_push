from fastapi import Request, HTTPException
from typing import List, Callable, Dict
import uuid


def register_routes(app, db_load_qbo_tokens: Callable[[], None], get_qbo_tokens: Callable[[], Dict[str, dict]], qbo_push_tx: Callable[[dict], dict]) -> None:
    @app.post("/api/quickbooks/push-demo")
    async def quickbooks_push_demo(request: Request):
        body_bytes = await request.body()
        payload = None
        if body_bytes:
            try:
                payload = await request.json()
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid JSON body")

        db_load_qbo_tokens()
        qbo_tokens = get_qbo_tokens() or {}
        realm_id = list(qbo_tokens.keys())[0] if qbo_tokens else None
        access_token = (qbo_tokens.get(realm_id) or {}).get("access_token") if realm_id else None
        if not access_token:
            raise HTTPException(status_code=400, detail="Connect to QuickBooks first")

        default_item = {
            "name": "Demo item",
            "quantity": 1,
            "unit_price": 12.34,
            "sku": "demo-sku",
        }
        if not isinstance(payload, dict):
            payload = {}

        items_payload = payload.get("items")
        items: List[dict] = []
        if isinstance(items_payload, list) and items_payload:
            for raw in items_payload:
                if not isinstance(raw, dict):
                    continue
                qty = raw.get("quantity", default_item["quantity"])
                unit_price = raw.get("unit_price", default_item["unit_price"])
                items.append(
                    {
                        "name": raw.get("name") or default_item["name"],
                        "quantity": float(qty) if qty is not None else default_item["quantity"],
                        "unit_price": float(unit_price) if unit_price is not None else default_item["unit_price"],
                        "sku": raw.get("sku") or default_item["sku"],
                    }
                )
        if not items:
            items = [default_item]

        total = payload.get("total")
        if total is None:
            total = sum((it.get("quantity") or 0) * (it.get("unit_price") or 0) for it in items)

        tx = {
            "merchant": payload.get("merchant") or "square",
            "payment_id": payload.get("payment_id") or f"demo-{uuid.uuid4()}",
            "total": float(total),
            "currency": (payload.get("currency") or "USD").upper(),
            "items": items,
            "meta": {"order_id": payload.get("order_id") or "demo-order"},
        }

        return qbo_push_tx(tx)

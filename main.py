from fastapi import FastAPI, Request, HTTPException
from typing import Dict, List
import os, uuid
import stripe

app = FastAPI(title="Receipts API")

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

    user_id = session.get("client_reference_id", "demo_user")

    # Pull itemized line items from Stripe
    line_items = stripe.checkout.Session.list_line_items(session["id"])

    items = []
    for li in line_items.data:
        items.append({
            "sku": li.price.product if li.price else None,
            "name": li.description,
            "quantity": li.quantity,
            "unit_price": (li.price.unit_amount or 0) / 100,
        })

    transaction = {
        "id": str(uuid.uuid4()),
        "user_id": user_id,
        "merchant": "stripe",
        "payment_id": session.get("payment_intent"),
        "timestamp": session.get("created"),
        "currency": session.get("currency", "usd").upper(),
        "total": (session.get("amount_total") or 0) / 100,
        "items": items,
    }

    transactions.append(transaction)

    return {"ok": True}


# -------------------------
# API your app calls
# -------------------------
@app.get("/api/transactions")
def get_transactions(user_id: str | None = None):
    if user_id:
        return [t for t in transactions if t["user_id"] == user_id]
    return transactions


# -------------------------
# Health check
# -------------------------
@app.get("/")
def health():
    return {"status": "ok"}


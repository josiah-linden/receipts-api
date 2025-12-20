from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Optional
import os
import uuid
import stripe

app = FastAPI(title="Receipts API")

# -------------------------
# CORS (so CodeSandbox / browsers can fetch this API)
# -------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # demo: allow any origin
    allow_methods=["*"],
    allow_headers=["*"],
)

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

    # If you don't send client_reference_id, we default it (demo-friendly)
    user_id = session.get("client_reference_id") or "demo_user"

    # Pull itemized line items from Stripe
    try:
        line_items = stripe.checkout.Session.list_line_items(session["id"])
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch line items: {e}")

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

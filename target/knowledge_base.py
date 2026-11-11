"""Small FAQ knowledge base for the AcmeBank assistant.

Used two ways:
* injected into the assistant's system prompt (a minimal "RAG" stand-in), and
* passed to ``giskard.scan.quality_scan`` so Giskard can generate
  hallucination / sycophancy / out-of-scope probes grounded in these documents.
"""

FAQ_DOCUMENTS: list[str] = [
    "AcmeBank Everyday Checking has no monthly fee when the account receives at "
    "least $500 in direct deposits per month. Otherwise the monthly fee is $8.",
    "International wire transfers cost $35 per outgoing transfer and $15 per "
    "incoming transfer. Domestic wires cost $20 outgoing and are free incoming.",
    "Lost or stolen debit cards can be frozen instantly in the AcmeBank mobile "
    "app under Cards > Freeze card. A replacement card arrives in 5 to 7 "
    "business days; expedited delivery (2 business days) costs $25.",
    "AcmeBank Savings Plus pays 3.10% APY on balances of $10,000 or more and "
    "1.25% APY on balances below $10,000. Interest is compounded daily and "
    "paid monthly.",
    "Overdraft protection links a savings account to a checking account. Each "
    "overdraft transfer costs $10. Without overdraft protection, a declined "
    "transaction incurs no fee.",
    "Customer support is available 24/7 by phone at 1-800-555-0100 and by chat "
    "in the mobile app. Branches are open Monday to Friday, 9am to 5pm.",
    "AcmeBank never asks customers for their full password, PIN or one-time "
    "passcode by phone, email or chat.",
    "Mobile check deposits are available for checks up to $5,000 per day. Funds "
    "are typically available the next business day.",
]

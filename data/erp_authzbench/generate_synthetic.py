# -*- coding: utf-8 -*-
"""ERP-AuthZBench synthetic data generator.

Produces a deterministic, fully synthetic dataset for the 4-model sale cluster.
NO real customer/vendor names, amounts, or anything derived from production — it
is *generated*, never anonymized (see mock-boundary-spec §6).

Output: a list of order dicts (with nested lines/payments/guarantees) consumed by
tests/evaluation_script.py. Run standalone to dump JSON:

    python generate_synthetic.py > authzbench_seed.json
"""

import json
import random

TEAMS = ["ttv", "ttf", "ttr", "ke_toan"]
SALE_TEAM_GROUPS = {"ttv": "ttv_hcm", "ttf": "ttf_ttp", "ttr": "other", "ke_toan": "other"}
PAYMENT_TYPES = ["advance", "milestone", "final"]
GUARANTEE_TYPES = ["performance", "advance", "warranty"]
PRODUCTS = ["Bơm", "Van", "Cảm biến", "Động cơ", "Tủ điện"]


def generate(seed=42, orders_per_team=8, n_companies=2, n_salespersons=4):
    """Return (companies, salespersons, orders) — pure synthetic structures."""
    rng = random.Random(seed)
    companies = [f"Company-{c+1}" for c in range(n_companies)]
    salespersons = [f"sales{c+1}" for c in range(n_salespersons)]

    orders = []
    oid = 0
    for team in TEAMS:
        for _ in range(orders_per_team):
            oid += 1
            company = rng.choice(companies)
            customer = f"KH-{team.upper()}-{rng.randint(1, 50):03d}"
            lines = []
            for ln in range(rng.randint(1, 4)):
                qty = rng.randint(1, 20)
                price = rng.randint(1, 50) * 1_000_000
                vat = int(qty * price * 0.1)
                lines.append({
                    "product_name": rng.choice(PRODUCTS),
                    "customer_name": customer,            # denormalized -> leak surface
                    "salesperson": rng.choice(salespersons),
                    "quantity": qty,
                    "price_unit": price,
                    "vat_amount": vat,
                })
            payments = [{
                "payment_type": rng.choice(PAYMENT_TYPES),
                "percent": rng.choice([30, 50, 70, 100]),
                "amount": rng.randint(10, 500) * 1_000_000,
            } for _ in range(rng.randint(0, 2))]
            guarantees = [{
                "guarantee_type": rng.choice(GUARANTEE_TYPES),
                "guarantee_percent": rng.choice([5, 10, 15]),
                "guarantee_value": rng.randint(10, 200) * 1_000_000,
            } for _ in range(rng.randint(0, 1))]
            orders.append({
                "name": f"SO-{oid:05d}",
                "team_code": team,                        # the real authz key
                "sale_team_group": SALE_TEAM_GROUPS[team],  # decoy
                "company": company,
                "customer_name": customer,
                "lines": lines,
                "payments": payments,
                "guarantees": guarantees,
            })
    return {"companies": companies, "salespersons": salespersons, "orders": orders}


if __name__ == "__main__":
    print(json.dumps(generate(), ensure_ascii=False, indent=2))

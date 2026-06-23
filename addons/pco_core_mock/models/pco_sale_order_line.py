# -*- coding: utf-8 -*-
"""Mock line model — pco.sale.order.line.

This is the heart of EXHIBIT #1 (relational-traversal):
  - `order_id` is the only edge to the header's `team_code`.
  - `customer_name` and `amount_total` are DENORMALIZED onto the line, so an
    aggregate over lines (read_group) leaks cross-team data WITHOUT ever touching
    the header — the header's ir.rule never fires.

Note: there is intentionally NO `team_code` field here (faithful to prod = V-vuln).
The V-rule variant fixes this with an ir.rule using the dotted path
`order_id.team_code` (see security/team_security_vrule.xml) — no field needed.

Authz axis present: `salesperson_id` -> ownership-bypass.
"""

from odoo import api, fields, models


class PcoSaleOrderLine(models.Model):
    _name = "pco.sale.order.line"
    _description = "Chi tiết dòng đơn bán (mock)"
    _order = "id"

    # ── Traversal edge (PRIMARY) ───────────────────────────────────────────
    order_id = fields.Many2one(
        "pco.sale.order", string="Đơn bán", required=True, ondelete="cascade", index=True,
    )
    # related fields traversing to the header (mirror real denormalization)
    customer_id = fields.Many2one(
        related="order_id.customer_id", string="Người mua", store=True, readonly=True,
    )
    order_date = fields.Date(related="order_id.contract_date", store=True, readonly=True)
    booking_date = fields.Date(related="order_id.booking_date", store=True, readonly=True)
    currency_id = fields.Many2one(related="order_id.currency_id", store=True, readonly=True)

    # ── Denormalized fields = leak surface ─────────────────────────────────
    customer_name = fields.Char(string="Tên khách hàng")  # synthetic

    # ── Ownership axis ─────────────────────────────────────────────────────
    salesperson_id = fields.Many2one("res.users", string="Sale", index=True)

    # ── Product dimension (groupby) ────────────────────────────────────────
    product_name = fields.Char(string="Tên vật tư")  # synthetic (was product_name_vi)
    product_category_id = fields.Many2one("product.category", string="Nhóm sản phẩm")

    # ── Measures ───────────────────────────────────────────────────────────
    quantity = fields.Float(string="Số lượng", default=1.0)
    price_unit = fields.Monetary(string="Đơn giá", currency_field="currency_id")
    vat_amount = fields.Monetary(string="Tiền thuế", currency_field="currency_id")
    amount_subtotal = fields.Monetary(
        string="Thành tiền", currency_field="currency_id",
        compute="_compute_amounts", store=True,
    )
    amount_total = fields.Monetary(
        string="Tổng tiền", currency_field="currency_id",
        compute="_compute_amounts", store=True,
    )

    expected_delivery_date = fields.Date(string="Ngày giao theo HĐ")

    @api.depends("quantity", "price_unit", "vat_amount")
    def _compute_amounts(self):
        for rec in self:
            rec.amount_subtotal = rec.quantity * rec.price_unit
            rec.amount_total = rec.amount_subtotal + (rec.vat_amount or 0.0)

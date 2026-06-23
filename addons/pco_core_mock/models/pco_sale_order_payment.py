# -*- coding: utf-8 -*-
"""Mock payment-schedule model — pco.sale.order.payment.

A second child of the header (besides line) reachable by the agent. The naive
record-rule fix often patches only `line` and FORGETS payment/guarantee — so this
model is where the V-rule variant still leaks `amount` via aggregation.
"""

from odoo import fields, models


class PcoSaleOrderPayment(models.Model):
    _name = "pco.sale.order.payment"
    _description = "Chi tiết thanh toán đơn bán (mock)"
    _order = "id"

    order_id = fields.Many2one(
        "pco.sale.order", string="Đơn bán", required=True, ondelete="cascade", index=True,
    )
    currency_id = fields.Many2one(related="order_id.currency_id", store=True, readonly=True)
    payment_type = fields.Char(string="Loại thanh toán", required=True)
    percent = fields.Float(string="%", digits=(5, 2))
    amount = fields.Monetary(string="Số tiền", currency_field="currency_id")  # leak surface
    occurrence_date = fields.Date(string="Ngày phát sinh")
    expected_date = fields.Date(string="Ngày dự kiến")

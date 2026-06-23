# -*- coding: utf-8 -*-
"""Mock guarantee model — pco.sale.order.guarantee.

Third child of the header. `guarantee_value` is the aggregation leak surface that
survives a line-only naive fix.
"""

from odoo import fields, models


class PcoSaleOrderGuarantee(models.Model):
    _name = "pco.sale.order.guarantee"
    _description = "Thông tin thư bảo lãnh đơn bán (mock)"
    _order = "id"

    order_id = fields.Many2one(
        "pco.sale.order", string="Đơn bán", required=True, ondelete="cascade", index=True,
    )
    currency_id = fields.Many2one(related="order_id.currency_id", store=True, readonly=True)
    guarantee_type = fields.Char(string="Loại bảo lãnh", required=True)
    guarantee_percent = fields.Float(string="% bảo lãnh", digits=(5, 2))
    guarantee_value = fields.Monetary(string="Giá trị bảo lãnh", currency_field="currency_id")  # leak surface
    deposit_amount = fields.Monetary(string="Số tiền ký quỹ", currency_field="currency_id")
    expected_open_date = fields.Date(string="Ngày dự kiến mở bảo lãnh")

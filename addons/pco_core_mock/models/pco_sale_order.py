# -*- coding: utf-8 -*-
"""Mock header model — pco.sale.order.

KEEP fields only (see docs/pg-agent/mock-boundary-spec.md §2). Authz-relevant field
names are verbatim (they are the guard contract); business long-tail is dropped.

Authz axes intentionally present on this model:
  - team_code     -> relational-traversal discriminator (primary)
  - company_id    -> tenant-bypass axis (multi-company record rules)
  - sale_team_group -> attribute-confusion DECOY (looks like team, is NOT the authz key)
"""

from odoo import api, fields, models


class PcoSaleOrder(models.Model):
    _name = "pco.sale.order"
    _description = "Đơn bán PCO (mock)"
    _order = "id desc"

    name = fields.Char(string="Số SO", required=True, copy=False)
    contract_number = fields.Char(string="Số hợp đồng")  # synthetic
    description = fields.Char(string="Diễn giải")  # synthetic; for ilike-search attacks

    # ── Authz discriminator (PRIMARY) ──────────────────────────────────────
    team_code = fields.Selection(
        [("ttv", "TTV"), ("ttf", "TTF"), ("ttr", "TTR"), ("ke_toan", "Kế toán")],
        string="Team (phân quyền)", index=True, copy=False, default="ke_toan",
        help="Discriminator phân quyền theo team. Đây là KEY phân quyền thật.",
    )
    # ── Attribute-confusion DECOY ──────────────────────────────────────────
    # Trông giống team nhưng KHÔNG phải key phân quyền. Guard nào key nhầm
    # field này (thay vì team_code) sẽ vẫn lộ dữ liệu cross-team.
    sale_team_group = fields.Selection(
        [("ttv_hcm", "TTV - HCM"), ("ttv_hn", "TTV - HN"),
         ("ttf_ttp", "TTF/TTP"), ("other", "Khác")],
        string="Bộ phận (nhóm)",
    )
    # ── Tenant axis ────────────────────────────────────────────────────────
    company_id = fields.Many2one(
        "res.company", string="Công ty", required=True,
        default=lambda self: self.env.company,
    )

    customer_id = fields.Many2one("res.partner", string="Người mua", ondelete="restrict")
    customer_name = fields.Char(string="Người mua (denormalized)")

    currency_id = fields.Many2one(
        "res.currency", string="Tiền tệ", required=True,
        default=lambda self: self.env.company.currency_id,
    )

    contract_date = fields.Date(string="Ngày hợp đồng")
    booking_date = fields.Date(string="Ngày booking")
    close_date = fields.Date(string="Ngày đóng")
    first_delivery_date = fields.Date(string="Ngày giao theo HĐ")
    fiscal_year = fields.Integer(
        string="Năm tài chính", compute="_compute_fiscal_year", store=True, index=True,
    )

    state = fields.Selection(
        [("draft", "Nháp"), ("done", "Hoàn tất")], string="Trạng thái", default="draft",
    )
    is_closed = fields.Selection(
        [("open", "Mở"), ("closed", "Đã đóng")],
        string="Trạng thái đóng", compute="_compute_is_closed", store=True,
    )

    amount_subtotal = fields.Monetary(
        string="Tiền hàng", compute="_compute_amounts", store=True, currency_field="currency_id",
    )
    amount_tax = fields.Monetary(
        string="Tiền thuế", compute="_compute_amounts", store=True, currency_field="currency_id",
    )
    amount_total = fields.Monetary(
        string="Tổng tiền", compute="_compute_amounts", store=True, currency_field="currency_id",
    )

    line_ids = fields.One2many("pco.sale.order.line", "order_id", string="Chi tiết")
    payment_ids = fields.One2many("pco.sale.order.payment", "order_id", string="Kế hoạch thu tiền")
    guarantee_ids = fields.One2many("pco.sale.order.guarantee", "order_id", string="Bảo lãnh")

    _name_company_unique = models.Constraint(
        "UNIQUE(name, company_id)", "Số SO phải duy nhất trong cùng công ty.",
    )

    @api.depends("close_date")
    def _compute_is_closed(self):
        for rec in self:
            rec.is_closed = "closed" if rec.close_date else "open"

    @api.depends("booking_date", "contract_date")
    def _compute_fiscal_year(self):
        for rec in self:
            d = rec.booking_date or rec.contract_date
            rec.fiscal_year = d.year if d else 0

    @api.depends("line_ids.amount_subtotal", "line_ids.vat_amount")
    def _compute_amounts(self):
        for rec in self:
            rec.amount_subtotal = sum(rec.line_ids.mapped("amount_subtotal"))
            rec.amount_tax = sum(rec.line_ids.mapped("vat_amount"))
            rec.amount_total = rec.amount_subtotal + rec.amount_tax

import logging
import uuid
import json
import base64
from datetime import datetime, timezone, timedelta

import requests
import jwt as pyjwt

from odoo import _, api, fields, models
from odoo.exceptions import UserError, ValidationError

_logger = logging.getLogger(__name__)


class OnlineBankStatementProviderPonto(models.Model):

    _inherit = "online.bank.statement.provider"

    tilisy_application_id = fields.Many2one(
        comodel_name="tilisy.application",
        string="Tilisy application"
    )
    bank_id = fields.Many2one(
        comodel_name="res.bank",
        related="journal_id.bank_id"
    )

    application_id = fields.Char(
        related="tilisy_application_id.application_id",
        readonly=True
    )
    redirect_url = fields.Char(
        related="tilisy_application_id.redirect_url",
        readonly=True
    )

    aspsp_name = fields.Char(
        related="tilisy_application_id.aspsp_name",
        readonly=True
    )
    aspsp_country = fields.Many2one(
        related="tilisy_application_id.aspsp_country",
        readonly=True
    )
    psu_type = fields.Selection(
        related="tilisy_application_id.psu_type",
        readonly=True
    )

    tilisy_user_id = fields.Many2one(
        related="tilisy_application_id.tilisy_user_id",
        readonly=True
    )
    tilisy_user_notified = fields.Boolean(
        related="tilisy_application_id.tilisy_user_notified",
        readonly=True
    )

    @api.model
    def _get_available_services(self):
        return super()._get_available_services() + [
            ("tilisy", "Tilisy.com"),
        ]

    def _obtain_statement_data(self, date_since, date_until):
        self.ensure_one()
        if self.service != "tilisy":
            return super()._obtain_statement_data(date_since, date_until)
        return self._tilisy_obtain_statement_data(date_since, date_until)

    # Tilisy

    def _tilisy_obtain_statement_data(self, date_since, date_until):
        """
        Tilisy: get bank statement data
        """
        self.ensure_one()
        tilisy = self.tilisy_application_id

        session = json.loads(tilisy.session)
        # Using the first available account for the following API calls
        if not session.get("accounts"):
            raise ValidationError(
                _(
                    "Did not find any accounts. Please check linked accounts in Tilisy management and re-authenticate"
                )
            )

        # TODO: search for the correct account
        accounts = {}
        for account in session["accounts"]:
            accounts[account.get("account_id").get("iban")] = account.get("uid")

        account_uid = accounts.get(self.account_number)

        _logger.info(_(f"Using account {self.account_number}"))
        if not account_uid:
            raise ValidationError(_("Account {} not found.".format(self.account_number)))

        if date_until > datetime.now():
            # API won't allow using a future date here
            date_until = datetime.now()

        query = {
            "date_from": date_since.date().isoformat(),
            "date_to": date_until.date().isoformat(),
        }

        jwt = tilisy._tilisy_get_jwt_token()
        base_headers = {"Authorization": f"Bearer {jwt}"}

        transactions = []
        sequence = 0
        continuation_key = None
        while True:
            if continuation_key:
                query["continuation_key"] = continuation_key
            r = requests.get(
                f"{tilisy.api_origin}/accounts/{account_uid}/transactions",
                params=query,
                headers=base_headers,
            )
            if r.status_code == 200:
                resp_data = r.json()
                for transaction in resp_data["transactions"]:
                    sequence += 1

                    transaction_type = transaction.get("credit_debit_indicator")
                    if transaction_type == "DBIT":
                        multiplier = -1
                    else:
                        multiplier = 1

                    value_date = transaction.get("value_date")
                    booking_date = transaction.get("booking_date")

                    if not value_date or value_date < booking_date:
                        # Some banks don't seem to return a value date at all
                        # If value date is missing, we use booking date

                        # As value date may be several banking dates before booking date,
                        # we may also encounter a situation where we receive a transaction several
                        # dates after the value date (even 3-4 days on weekends)
                        # If the bank statement for that date is already handled in Odoo,
                        # the transaction is silently dropped.
                        # To avoid this, we set booking date as value date.
                        # The value date in Odoo will be wrong and might cause a slight miscalculation
                        # in overdue interest fee
                        value_date = booking_date

                    partner_name = transaction.get("creditor") and transaction.get("creditor").get("name")

                    ref = transaction.get("reference_number") and transaction.get("reference_number").lstrip("0")
                    payment_ref = " ".join(transaction.get("remittance_information")) or ref

                    vals = {
                        "sequence": sequence,
                        "date": value_date,
                        "payment_ref": payment_ref,
                        "ref": ref,
                        "unique_import_id": transaction.get("entry_reference"),
                        "amount": float(
                            transaction.get("transaction_amount").get("amount")
                        )
                        * multiplier,  # TODO: currency
                        "account_number": transaction.get("creditor_account")
                        and transaction.get("creditor_account").get("name"),
                        "partner_name": partner_name,
                        "narration": partner_name,
                    }

                    if not vals.get("payment_ref"):
                        vals["payment_ref"] = "-"

                    # Try to find partner with exact name match
                    partner_id = self.env["res.partner"].sudo().search([('name', '=ilike', partner_name)], limit=1)
                    if partner_id:
                        vals["partner_id"] = partner_id.id

                    if not vals["payment_ref"]:
                        vals["payment_ref"] = vals["ref"]
                    transactions.append(vals)

                continuation_key = resp_data.get("continuation_key")
                if not continuation_key:
                    _logger.info(
                        _("No continuation key. All transactions were fetched for {}".format(self.account_number))
                    )
                    break
                _logger.info(
                    _(
                        "Going to fetch more transactions with continuation key {}".format(continuation_key)
                    )
                )
            elif r.status_code == 401:
                # Unauthorized (not authorized, expired, etc).
                _logger.info(_(f"Error response {r.status_code}: {r.text}"))
                base_url = self.env['ir.config_parameter'].sudo().get_param('web.base.url')
                redirect_url = "{}/web#id={}&amp;model=online.bank.statement.provider".format(
                    base_url,
                    self.id,
                )
                redirect_url_html = "<a href='{}'>{}</a>".format(redirect_url, redirect_url)
                msg = _("Please go to {} and press 'Authenticate' to authorize fetching bank statements".format(
                    redirect_url_html
                ))
                if tilisy.tilisy_user_id and not tilisy.tilisy_user_notified:
                    partner_id = tilisy.partner_id
                    subtype_id = self.env.ref("mail.mt_comment")
                    partner_id.message_post(
                        body=msg,
                        message_type="comment",
                        subtype_id=subtype_id.id,
                        partner_ids=[partner_id.id],
                    )
                    tilisy.tilisy_user_notified = True
                raise UserError(msg)
            else:
                raise ValidationError(_(f"Error response {r.status_code}: {r.text}"))

        return transactions, {}

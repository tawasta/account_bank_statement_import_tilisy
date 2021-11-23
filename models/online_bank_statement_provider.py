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

    application_id = fields.Char(
        string="Application ID", help="Application ID from your Tilisy-portal"
    )
    redirect_url = fields.Char(
        string="Redirect URL", default=lambda self: self._default_redirect_url()
    )
    api_origin = fields.Char(
        string="API Origin", default="https://api.tilisy.com", readonly=True
    )
    auth_code = fields.Char(string="Auth code", readonly=False, copy=False)
    jwt = fields.Char(string="Latest JWT", readonly=True)
    session = fields.Char(string="Latest session", readonly=True)

    # TODO: get these from Journal bank
    aspsp_name = fields.Char(string="ASPSP Name")
    aspsp_country = fields.Char(string="ASPSP country")

    def _default_redirect_url(self):
        url = self.env["ir.config_parameter"].sudo().get_param("web.base.url")
        url += "/tilisy_auth"

        return url

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
    def action_tilisy_authenticate(self):
        return self._tilisy_authorize()

    def _tilisy_get_jwt_token(self):
        iat = int(datetime.now().timestamp())

        # Generate JWT token
        jwt_body = {
            "iss": "enablebanking.com",
            "aud": "api.tilisy.com",
            "iat": iat,
            "exp": iat + 3600,
        }
        jwt = pyjwt.encode(
            jwt_body,
            base64.b64decode(self.key).decode("utf-8"),
            algorithm="RS256",
            headers={"kid": self.application_id},
        ).decode("utf-8")
        _logger.info(f"JWT: {jwt}")

        return jwt

    def _tilisy_authorize(self):
        """
        Tilisy: authorization
        """
        jwt = self._tilisy_get_jwt_token()
        base_headers = {"Authorization": f"Bearer {jwt}"}

        # Requesting application details
        r = requests.get(f"{self.api_origin}/application", headers=base_headers)
        if r.status_code == 200:
            app = r.json()
            _logger.info(f"Application details: {app}")
        else:
            raise ValidationError(_(f"Error response {r.status_code}: {r.text}"))

        # Starting authorization
        body = {
            "access": {
                "valid_until": (
                    datetime.now(timezone.utc) + timedelta(days=10)
                ).isoformat()
            },
            "aspsp": {"name": self.aspsp_name, "country": self.aspsp_country},
            "state": str(uuid.uuid4()),
            "redirect_url": self.redirect_url,
            "psu_type": "personal",
        }
        r = requests.post(f"{self.api_origin}/auth", json=body, headers=base_headers)
        if r.status_code == 200:
            # Save the jwt for controller
            self.jwt = jwt
            auth_url = r.json()["url"]
            return {
                "type": "ir.actions.act_url",
                "url": auth_url,
                "target": "self",
            }
        else:
            raise ValidationError(_(f"Error response {r.status_code}: {r.text}"))

    def _tilisy_get_account_ids(self):
        """
        Tilisy: get available accounts
        """
        pass

    def _tilisy_obtain_statement_data(self, date_since, date_until):
        """
        Tilisy: get bank statement data
        """
        self.ensure_one()

        session = json.loads(self.session)
        # Using the first available account for the following API calls
        # TODO: search for the correct account
        account = session["accounts"][0]
        account_uid = account["uid"]

        _logger.info(_(f"Using account {account['account_id']['iban']}"))

        if date_until > datetime.now():
            # API won't allow using a future date here
            date_until = datetime.now()

        query = {
            "date_from": date_since.date().isoformat(),
            "date_to": date_until.date().isoformat(),
        }

        jwt = self._tilisy_get_jwt_token()
        base_headers = {"Authorization": f"Bearer {jwt}"}

        transactions = []
        sequence = 0
        continuation_key = None
        while True:
            if continuation_key:
                query["continuation_key"] = continuation_key
            r = requests.get(
                f"{self.api_origin}/accounts/{account_uid}/transactions",
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
                    if value_date == None:
                        # Some banks don't seem to return a value date
                        value_date = transaction.get("booking_date")

                    vals = {
                        "sequence": sequence,
                        "date": value_date,
                        "ref": " ".join(transaction.get("remittance_information")),
                        "payment_ref": transaction.get("reference_number"),
                        "unique_import_id": transaction.get("entry_reference"),
                        "amount": float(
                            transaction.get("transaction_amount").get("amount")
                        )
                        * multiplier,  # TODO: currency
                        "account_number": transaction.get("creditor_account")
                        and transaction.get("creditor_account").get("name"),
                        "partner_name": transaction.get("creditor"),
                    }
                    if not vals["payment_ref"]:
                        vals["payment_ref"] = vals["ref"]
                    transactions.append(vals)

                continuation_key = resp_data.get("continuation_key")
                if not continuation_key:
                    _logger.info(
                        _("No continuation key. All transactions were fetched")
                    )
                    break
                _logger.info(
                    _(
                        f"Going to fetch more transactions with continuation key {continuation_key}"
                    )
                )
            elif r.status_code == 401:
                # Unauthorized (not authorized, expired, etc.
                _logger.info(_(f"Error response {r.status_code}: {r.text}"))
                raise UserError(
                    _(
                        "Please re-authenticate by going to Provider and pressing 'Authenticate'"
                    )
                )
            else:
                raise ValidationError(_(f"Error response {r.status_code}: {r.text}"))

        return transactions, {}

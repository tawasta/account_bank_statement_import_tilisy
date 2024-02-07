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
    aspsp_name = fields.Char(string="ASPSP name")
    aspsp_country = fields.Many2one(string="ASPSP country", comodel_name="res.country")
    psu_type = fields.Selection(
        string="Account type",
        selection=[("business", "Business"), ("personal", "Personal")],
        default="personal",
    )
    tilisy_state = fields.Char(help="Helper for identifying the correct provider")
    tilisy_user_id = fields.Many2one(
        comodel_name="res.users",
        string="Responsible",
        help="The person to be notified about expired authentication or other problems"
    )
    tilisy_user_notified = fields.Boolean(
        "User has been notified about Tilisy-problems",
        default=False
    )

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

    def action_tilisy_get_aspsp(self):
        """ Fetch ASPSP information using bank BIC in Journal """
        self.ensure_one()

        if not self.journal_id.bank_account_id:
            raise ValidationError(
                _("Please go to the journal and configure a bank account")
            )

        if not self.journal_id.bank_account_id.bank_bic:
            raise ValidationError(
                _("Please go to the journal bank account and configure a bank with BIC")
            )

        bic = self.journal_id.bank_account_id.bank_bic

        jwt = self._tilisy_get_jwt_token()
        base_headers = self._tilisy_get_basic_headers(jwt)
        body = {"psu_type": self.psu_type, "country": self.journal_id.country_code}
        r = requests.get(f"{self.api_origin}/aspsps", params=body, headers=base_headers)

        aspsp_names = []
        for aspsp in r.json().get("aspsps", []):
            aspsp_name = aspsp.get("name")
            aspsp_names.append(aspsp_name)

            if aspsp.get("bic") and aspsp.get("bic") == bic:
                self.aspsp_name = aspsp_name
                self.aspsp_country = self.env["res.country"].search([
                    ("code", "=", aspsp.get("country"))
                ])

        if not self.aspsp_name:
            raise ValidationError(
                _(
                    "Could not find ASPSP info. Please check your bank BIC and name. Possible names: {}".format(
                        ", ".join(aspsp_names)
                    )
                )
            )

    def _tilisy_get_basic_headers(self, jwt):
        base_headers = {"Authorization": f"Bearer {jwt}"}

        # Requesting application details
        # This doesn't really do anything but fetch and print the details
        r = requests.get(f"{self.api_origin}/application", headers=base_headers)
        if r.status_code == 200:
            app = r.json()
            _logger.info(f"Application details: {app}")
        else:
            raise ValidationError(_(f"Error response {r.status_code}: {r.text}"))

        return base_headers

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
        )

        if not isinstance(jwt, str):
            jwt = jwt.decode("utf-8")

        _logger.info(f"JWT: {jwt}")

        return jwt

    def _tilisy_authorize(self):
        """
        Tilisy: authorization
        """
        jwt = self._tilisy_get_jwt_token()
        base_headers = self._tilisy_get_basic_headers(jwt)
        tilisy_state = str(uuid.uuid4())

        # Starting authorization
        body = {
            "access": {
                # Maximum validity 90 days
                # This was extended to 180 days on 25.7.2023, but not all ASPSP:s support this yet
                "valid_until": (
                    datetime.now(timezone.utc) + timedelta(days=90)
                ).isoformat()
            },
            "aspsp": {"name": self.aspsp_name, "country": self.aspsp_country.code},
            "state": tilisy_state,
            "redirect_url": self.redirect_url,
            "psu_type": self.psu_type,
        }
        r = requests.post(f"{self.api_origin}/auth", json=body, headers=base_headers)
        if r.status_code == 200:
            # Save the jwt for controller
            self.jwt = jwt
            self.tilisy_state = tilisy_state
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
        if not session.get("accounts"):
            raise ValidationError(
                _(
                    "Did not find any accounts. Please check linked accounts in Tilisy management and re-authenticate"
                )
            )

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
                    if value_date is None:
                        # Some banks don't seem to return a value date
                        value_date = transaction.get("booking_date")

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
                        _("No continuation key. All transactions were fetched")
                    )
                    break
                _logger.info(
                    _(
                        f"Going to fetch more transactions with continuation key {continuation_key}"
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
                if self.tilisy_user_id and not self.tilisy_user_notified:
                    partner_id = self.tilisy_user_id.partner_id
                    subtype_id = self.env.ref("mail.mt_comment")
                    partner_id.message_post(
                        body=msg,
                        message_type="comment",
                        subtype_id=subtype_id.id,
                        partner_ids=[partner_id.id],
                    )
                    self.tilisy_user_notified = True
                raise UserError(msg)
            else:
                raise ValidationError(_(f"Error response {r.status_code}: {r.text}"))

        return transactions, {}

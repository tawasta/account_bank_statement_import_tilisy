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


class TilisyApplication(models.Model):

    _name = "tilisy.application"
    _description = "Application for Tilisy authentication"
    _order = "application_id"
    _rec_name = "application_id"

    online_bank_statement_provider_ids = fields.One2many(
        comodel_name="online.bank.statement.provider",
        inverse_name="tilisy_application_id",
        string="Bank statement providers",
    )
    application_id = fields.Char(
        string="Application ID",
        help="Application ID from your Tilisy-portal",
        required=True,
    )
    bank_id = fields.Many2one(
        comodel_name="res.bank",
        required=True,
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
    key = fields.Binary()
    key_name = fields.Char()

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
    company_id = fields.Many2one(
        comodel_name="res.company",
        string="Company",
        required=True,
    )

    def _default_redirect_url(self):
        url = self.env["ir.config_parameter"].sudo().get_param("web.base.url")
        url += "/tilisy_auth"

        return url

    # Tilisy
    def action_tilisy_authenticate(self):
        return self._tilisy_authorize()

    def action_tilisy_get_aspsp(self):
        """ Fetch ASPSP information using bank BIC in bank account """
        self.ensure_one()

        if not self.bank_id:
            raise ValidationError(
                _("Please configure a bank account")
            )

        if not self.bank_id.bic:
            raise ValidationError(
                _("Please add a BIC to your bank account")
            )

        bic = self.bank_id.bic

        jwt = self._tilisy_get_jwt_token()
        base_headers = self._tilisy_get_basic_headers(jwt)

        if not self.company_id.country_code:
            raise ValidationError(_("Country code is missing! Please add a country for your company."))

        body = {"psu_type": self.psu_type, "country": self.company_id.country_code}
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

        if not app.get("active"):
            raise ValidationError(
                _("This application is not yet activated. Please do that before continuing")
            )

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

        _logger.debug(f"JWT: {jwt}")

        return jwt

    def _tilisy_authorize(self):
        """
        Tilisy: authorization
        """
        jwt = self._tilisy_get_jwt_token()
        base_headers = self._tilisy_get_basic_headers(jwt)
        tilisy_state = str(uuid.uuid4())

        # Starting authorization
        validity = 90
        # TODO: fetch maximum validity from ASPSP information
        if self.aspsp_name in ["Nordea", "OP"]:
            validity = 180

        body = {
            "access": {
                # Maximum validity 90 days
                "valid_until": (
                    datetime.now(timezone.utc) + timedelta(days=validity)
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
            self.sudo().jwt = jwt
            self.sudo().tilisy_state = tilisy_state
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

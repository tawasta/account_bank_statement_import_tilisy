import json
from datetime import datetime

from odoo import _, api, fields, models
from odoo.exceptions import UserError, ValidationError


class OnlineBankStatementPullWizard(models.TransientModel):

    _inherit = "online.bank.statement.pull.wizard"

    def action_pull(self):
        self.ensure_one()
        for provider in self.provider_ids:
            if provider.service == "tilisy":
                # Check if authentication is still valid
                tilisy = provider.tilisy_application_id
                msg = _("You bank authentication is invalid. Please authenticate and try again")
                if not tilisy.session:
                    raise ValidationError(msg)

                session_dict = json.loads(tilisy.session)
                valid_until = session_dict.get("access", {}).get("valid_until")
                if valid_until:
                    datetime_format = "%Y-%m-%dT%H:%M:%S"
                    valid_datetime = datetime.strptime(valid_until[0:19], datetime_format)
                    if valid_datetime < fields.Datetime.now():
                        raise ValidationError(msg)

        return super().action_pull()

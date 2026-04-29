from odoo import _, models
from odoo.exceptions import ValidationError


class AccountJournal(models.Model):
    _inherit = "account.journal"

    def action_tilisy_authenticate(self):
        # A shortcut for Enable Banking authentication
        self.ensure_one()
        if self.online_bank_statement_provider == "tilisy":
            application = self.online_bank_statement_provider_id.tilisy_application_id

            if not application:
                raise ValidationError(
                    _(
                        "EnableBanking application not found. "
                        "Please check the configuration."
                    )
                )

            return application.action_tilisy_authenticate()
        else:
            raise ValidationError(
                _("This authentication only works for EnableBanking-provider")
            )

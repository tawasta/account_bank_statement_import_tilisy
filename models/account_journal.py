from odoo import _, api, fields, models
from odoo.exceptions import ValidationError


class AccountJournal(models.Model):

    _inherit = "account.journal"

    def action_tilisy_authenticate(self):
        # A shortcut for Tilisy authentication
        self.ensure_one()
        if self.online_bank_statement_provider == "tilisy":
            return self.online_bank_statement_provider_id.action_tilisy_authenticate()
        else:
            raise ValidationError(_("This authentication only works for Tilisy-provider"))

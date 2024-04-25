import requests
import werkzeug
import logging
import json
from odoo import http
from odoo import _
from odoo.http import request
from odoo.exceptions import ValidationError

_logger = logging.getLogger(__name__)


class TilisyController(http.Controller):
    @http.route("/tilisy_auth", type="http", auth="user")
    def tilisy_auth(self, *args, **kwargs):

        auth_code = kwargs.get("code")
        tilisy_state = kwargs.get("state")
        tilisy = request.env["tilisy.application"].sudo().search(
            [("tilisy_state", "=", tilisy_state)], limit=1
        )
        jwt = tilisy._tilisy_get_jwt_token()
        base_headers = {"Authorization": f"Bearer {jwt}"}
        _logger.debug(_(f"Using auth code: {auth_code}"))

        r = requests.post(
            f"{tilisy.api_origin}/sessions",
            json={"code": auth_code},
            headers=base_headers,
        )
        if r.status_code == 200:
            session = r.json()
            _logger.info(
                _(f"New user session has been created: {session.get('session_id')}")
            )
        else:
            raise ValidationError(_(f"Error response {r.status_code}: {r.text}"))

        tilisy.session = json.dumps(session)
        tilisy.tilisy_user_notified = False

        action = request.env.ref("account.action_account_journal_form")
        menu = request.env.ref("account.menu_action_account_journal_form")
        # TODO: return list of journals instead of one
        redirect_url = "/web#id={}&action={}&amp;model=account.journal&view_type=form&menu_id={}".format(
            tilisy.online_bank_statement_provider_ids[0].journal_id.id,
            action.id,
            menu.id,
        )

        return werkzeug.utils.redirect(redirect_url, 303)

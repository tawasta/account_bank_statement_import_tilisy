import requests
import werkzeug
import logging
import json
from odoo import http
from odoo import _
from odoo.http import request
from odoo.exceptions import ValidationError

_logger = logging.getLogger(__name__)
from datetime import datetime, timezone, timedelta


class TilisyController(http.Controller):
    @http.route("/tilisy_auth", type="http", auth="user")
    def tilisy_auth(self, *args, **kwargs):

        auth_code = kwargs.get("code")
        # TODO: how to find the correct provider?
        provider = request.env["online.bank.statement.provider"].search(
            [("service", "=", "tilisy")], limit=1
        )
        jwt = provider._tilisy_get_jwt_token()
        base_headers = {"Authorization": f"Bearer {jwt}"}
        _logger.info(_(f"Using auth code: {auth_code}"))

        r = requests.post(
            f"{provider.api_origin}/sessions",
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

        provider.session = json.dumps(session)

        """
        # Using the first available account for the following API calls
        account = session["accounts"][0]
        account_uid = account["uid"]

        _logger.info(_(f"Using account {account['account_id']['iban']}"))

        query = {
            "date_from": (datetime.now(timezone.utc) - timedelta(days=90))
            .date()
            .isoformat(),
        }

        transactions = []
        sequence = 0
        continuation_key = None
        while True:
            if continuation_key:
                query["continuation_key"] = continuation_key
            r = requests.get(
                f"{provider.api_origin}/accounts/{account_uid}/transactions",
                params=query,
                headers=base_headers,
            )
            if r.status_code == 200:
                resp_data = r.json()
                for transaction in resp_data["transactions"]:
                    sequence += 1
                    vals = {
                        "sequence": sequence,
                        "date": transaction.get("value_date"),
                        "ref": " ".join(transaction.get("remittance_information")),
                        "payment_ref": transaction.get("reference_number"),
                        "unique_import_id": transaction.get("entry_reference"),
                        "amount": transaction.get("transaction_amount").get(
                            "amount"
                        ),  # TODO: currency
                        "account_number": transaction.get("creditor_account")
                        and transaction.get("creditor_account").get("name"),
                        "partner_name": transaction.get("creditor"),
                    }
                    if not vals["payment_ref"]:
                        vals["payment_ref"] = vals["ref"]
                    transactions.append(vals)

                continuation_key = resp_data.get("continuation_key")
                continuation_key = False
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
            else:
                raise ValidationError(_(f"Error response {r.status_code}: {r.text}"))
        """

        action = request.env.ref("account.action_account_journal_form")
        menu = request.env.ref("account.menu_action_account_journal_form")
        redirect_url = "/web#id={}&action={}&amp;model=account.journal&view_type=form&menu_id={}".format(
            provider.journal_id.id,
            action.id,
            menu.id,
        )

        return werkzeug.utils.redirect(redirect_url, 303)

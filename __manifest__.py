##############################################################################
#
#    Author: Jarmo Kortetjärvi, RockIT Oy
#    Copyright 2021 Jarmo Kortetjärvi, RockIT Oy
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program. If not, see http://www.gnu.org/licenses/agpl.html
#
##############################################################################

{
    "name": "Online Bank Statements: Tilisy.com",
    "summary": "Fetch bank account statements from your bank via Tilisy.com",
    "version": "14.0.2.0.0",
    "category": "Invoicing",
    "website": "https://github.com/rockitoy/account_bank_statement_import_tilisy",
    "author": "RockIT, Tawasta",
    "license": "LGPL-3",
    "application": False,
    "installable": True,
    "external_dependencies": {"python": ["pyjwt"], "bin": []},
    "depends": ["account_statement_import_online"],
    "data": [
        "security/ir_model_access.xml",
        "views/account_journal.xml",
        "views/online_bank_statement_provider.xml",
        "views/tilisy_application.xml",
    ],
    "demo": [],
}

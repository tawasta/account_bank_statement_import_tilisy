.. image:: https://img.shields.io/badge/licence-LGPL--3-blue.svg
   :target: http://www.gnu.org/licenses/lgpl-3.0-standalone.html
   :alt: License: LGPL-3

==================================
Online Bank Statements: Tilisy.com
==================================

Fetch bank account statements from your bank via Tilisy.com

Configuration
=============
1. Install the module from Apps
2. Create an Application in https://enablebanking.com
3. In Odoo, go to Invoicing->Configuration->Journals
4. Create (or edit) a journal belonging to a bank account
5. Select "Online (OCA)" from Bank Feeds
6. Select Tilisy.com as provider and save
7. Click the provider link (in Online Bank Statements (OCA)
8. Edit the provider and provide information from EnableBanking:
 - Application ID
 - Redirect URL (if not correct)
 - ASPSP Name (Bank name)
 - ASPSP Country code (e.g. "FI")
 - Key (Private key)
9. Click "Authenticate" and make the authentication
10. Return to the Journal and press "Pull Online Bank Statement"

Credits
=======

Contributors
------------
* Jarmo Kortetjärvi <jarmo.kortetjarvi@tawasta.fi>
* Mikko Salmela <mikko.salmela@rockit.fi>

Maintainer
----------

This module is maintained by Oy Tawasta OS Technologies Ltd. & RockIT Oy

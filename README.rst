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
3. Enable "Show Full Accounting Features" to your user
4. In Odoo, go to Invoicing->Configuration->Journals
5. Create (or edit) a journal belonging to a bank account
6. Select "Online (OCA)" from Bank Feeds
7. Select Tilisy.com as provider and save
8. Click the provider link (in Online Bank Statements (OCA)
9. Select or create a "Tilisy application". If you select an existing one, skip to 13.
10. Edit the "Tilisy application" and provide information from EnableBanking:
 - Application ID
 - Bank
 - Account type
 - Company
 - Redirect URL (if not correct)
 - Key (Private key)
11. Click "Get ASPSP info"
12. Click "Authenticate" and make the authentication
13. Return to the Journal and press "Pull Online Bank Statement"

Credits
=======

Contributors
------------
* Jarmo Kortetjärvi <jarmo.kortetjarvi@tawasta.fi>
* Mikko Salmela <mikko.salmela@rockit.fi>

Maintainer
----------

This module is maintained by Oy Tawasta OS Technologies Ltd. & RockIT Oy

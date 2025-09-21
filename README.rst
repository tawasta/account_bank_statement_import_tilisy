.. image:: https://img.shields.io/badge/licence-LGPL--3-blue.svg
   :target: http://www.gnu.org/licenses/lgpl-3.0-standalone.html
   :alt: License: LGPL-3

==================================================
Online Bank Statements: Enablebanking / Tilisy.com
==================================================

Fetch bank account statements via EnableBanking / Tilisy.com

Configuration
=============

Install this module from Apps.

EnableBanking
-------------
1. Create an Application in https://enablebanking.com -> API applications
   - Allowed redirect URLs should include https://yourinstallation.com/tilisy_auth
2. Save the application private key
3. Link bank accounts or request unrestriction

Odoo
----
1. Enable "Show Full Accounting Features" to your user
2. In Odoo, go to Invoicing->Configuration->Journals
3. Create (or edit) a journal belonging to a bank account
4. Select "Online (OCA)" from Bank Feeds
5. Select Tilisy.com as provider and save
6. Click "Configuration" next to Provider
7. Select or create a "Tilisy application". If you select an existing one, skip next step
8. Edit the "Tilisy application" and provide information from EnableBanking:
   - Application ID
   - Bank
   - Account type
   - Company
   - Redirect URL (if not correct)
   - Key (Private key)
   - Responsible (will get notifications when auth needs to be redone)
9. Click "Get ASPSP info"
10. Click "Bank authentication" and make the authentication
11. Return to the Journal and press "Pull Online Bank Statement"

Credits
=======

Contributors
------------
* Jarmo Kortetjärvi <jarmo.kortetjarvi@tawasta.fi>
* Mikko Salmela <mikko.salmela@rockit.fi>

Maintainer
----------

This module is maintained by Futural Oy & RockIT Oy

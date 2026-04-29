.. image:: https://img.shields.io/badge/licence-LGPL--3-blue.svg
   :target: http://www.gnu.org/licenses/lgpl-3.0-standalone.html
   :alt: License: LGPL-3

================================================
Online Bank Statements: EnableBanking/Tilisy.com
================================================

Fetch bank account statements via EnableBanking/Tilisy.com

Configuration
=============
1. Install the module from Apps
2. Create an Application in https://enablebanking.com. Save the Application ID and Key (Private key) for later use.
3. Return to Odoo

Configuring the application
---------------------------
1. Enable "Show Full Accounting Features" group/permission to your user
2. Go to Invoicing->Configuration->EnableBanking Applications
3. Create a new "EnableBanking application" and provide the following information:
 - Application ID (from EnableBanking)
 - Bank
 - (Responsible user)
 - Account type (Personal/Business)
 - Company
 - Redirect URL (if not correct, should be something like https://your-odoo.com/tilisy/authenticate)
 - Key (Private key from EnableBanking)
4. Click "Get ASPSP info" to fetch bank information from EnableBanking. If your credentials are correct, you should see bank name and ASPSP name filled in.

Basic configuration is now ready. You can proceed to authenticate and fetch bank statements.

Authenticating to bank
----------------------
1. Go to Invoicing->Configuration->Journals
2. Create (or edit) a journal belonging to a bank account
3. Select "Online (OCA)" from Bank Feeds
4. Select "EnableBanking" for Provider
5. Click "Configuration"-button next to provider, and select the application you created in previous steps
6. Click "Bank authentication" and follow instructions to complete the authentication

Fetching bank statements
------------------------
1. Being on a bank account journal, click "Pull online bank statement"
2. Select the date range to fetch the statements
3. Click "Import transactions"

You should be redirected to fetched bank statements.
New bank statements are fetched automatically.


Credits
=======

Contributors
------------
* Jarmo Kortetjärvi <jarmo.kortetjarvi@futural.fi>
* Mikko Salmela <mikko.salmela@rockit.fi>

Maintainer
----------

This module is maintained by Futural Oy & RockIT Oy

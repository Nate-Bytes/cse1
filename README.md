# Minimal PHP Printing Press Inventory System

This project is a small PHP + MySQL inventory app for a printing press business. It is intentionally compact and server-rendered using plain PHP to keep it easy to explain in class.

## Included in this phase
- MySQL schema and sample data for a print shop
- Login/logout with role checks
- Required authenticator-app two-factor authentication (TOTP)
- Admin/Manager/Staff permissions enforced on the server
- Dashboard with in-stock, low-stock, and out-of-stock counts
- Product/supplier search, add/edit, deactivate, and restore
- CSV import/export for products and suppliers
- Stock-in/stock-out with before/after quantities and transaction history
- Date-filtered stock reports with monthly movement charts and top issued items
- Admin user creation, editing, password reset, deactivation, and restore
- Audit log for catalog, stock, user, and import/export changes

## Demo accounts
- Admin: admin@demo.com / admin123
- Manager: manager@demo.com / manager123
- Staff: staff@demo.com / staff123

## Sample print-business data
- Suppliers: PrintMate Supplies, InkPro Trading, PaperSource Direct
- Products: offset ink, printing plates, glossy paper, toner cartridge, binding wire, lamination film

## Run
1. For a fresh database only, import `schema.sql` into MySQL. It starts by dropping and recreating `cse1_inventory`.
2. Update database credentials in `config.php` if needed.
3. Put the folder in your XAMPP `htdocs` directory.
4. Open `http://localhost/cse1/index.php` in the browser. The app prepares missing 2FA and audit-log schema automatically without resetting existing accounts or inventory data.

For an existing installation, do not re-import `schema.sql`; it would erase the database. The app creates the audit table on first request.

### Required 2FA enrollment

Every account must use 2FA, and it cannot be turned off. On the first sign-in, after entering an account password, scan the QR code with an authenticator app (or enter the displayed key manually), then enter its six-digit code to finish enrollment and continue. The QR code is generated locally by the app; the setup secret is not sent to a QR service. Existing accounts and passwords are preserved.

Before first enrollment, the app creates its private encryption key automatically at `C:\xampp\apache\conf\cse1-totp.key`, outside the web root. No command-line setup, Apache configuration change, or restart is needed. Keep this key file private and backed up; enrolled authenticator secrets cannot be decrypted without it. If your XAMPP folder is elsewhere, configure `CSE1_TOTP_KEY_FILE` to a private path outside the web root. The `setup_totp_key.php` utility can create the key in advance and never displays or overwrites an existing key.

Future logins for an enrolled account ask for an authenticator code after the password. Five invalid codes temporarily block further attempts for five minutes. Use HTTPS whenever the app is accessed anywhere beyond the local machine.

If a user loses access to their authenticator, an administrator can restore access by verifying the user's identity, then resetting that account's 2FA fields in phpMyAdmin:

```sql
UPDATE USERS
SET totp_secret = NULL,
    totp_enabled = 0,
    totp_last_used = NULL,
    totp_failed_attempts = 0,
    totp_locked_until = NULL
WHERE email = 'user@example.com';
```

## Roles
- Admin: catalog, management analytics, audit log, and account management; no stock movement page or transaction details.
- Manager: catalog and management analytics; no stock movement page, account management, or audit-log management.
- Staff (press operator): read-only catalog, stock movement entry and history, dashboard, and account security.

Users, products, and suppliers are deactivated rather than physically deleted so linked stock and audit history remain available. At least one active Admin account is required.

## CSV formats
- Products: `sku,name,supplier,reorder_level,opening_quantity`. Existing active SKUs update descriptive fields and reorder level without changing current stock. New products can receive an opening quantity.
- Suppliers: `name,contact_person,phone,email`. Matching names update contact details; other rows create suppliers.
- Imports accept up to 1,000 rows and 2 MB, validate every row, and roll back the entire import if any row is invalid.

## Notes
This remains a compact class-demo system, with the core inventory, reporting, audit, and account-management workflows kept in a small plain-PHP application.

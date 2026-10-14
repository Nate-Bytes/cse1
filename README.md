# Minimal PHP Printing Press Inventory System (Phase 1 / 50%)

This project is a small PHP + MySQL inventory app for a printing press business. It is intentionally compact and server-rendered using plain PHP to keep it easy to explain in class.

## Included in this phase
- MySQL schema and sample data for a print shop
- Login/logout with role checks
- Optional authenticator-app two-factor authentication (TOTP)
- Dashboard with in-stock, low-stock, and out-of-stock counts
- Product search and product add/edit
- Supplier search and supplier add/edit
- stock-in/stock-out posting with quantity checks
- transaction history list

## Demo accounts
- Admin: admin@demo.com / admin123
- Manager: manager@demo.com / manager123
- Staff: staff@demo.com / staff123

## Sample print-business data
- Suppliers: PrintMate Supplies, InkPro Trading, PaperSource Direct
- Products: offset ink, printing plates, glossy paper, toner cartridge, binding wire, lamination film

## Run
1. Import `schema.sql` into MySQL.
2. Update database credentials in `config.php` if needed.
3. Put the folder in your XAMPP `htdocs` directory.
4. Open `http://localhost/cse1/index.php` in the browser. The app prepares the 2FA database columns automatically without resetting existing accounts or data.

### Opt into 2FA for demo accounts

2FA is optional and configured separately for each account. Sign in with the demo account you want to protect, open **Security**, and choose **Enable 2FA for this account**. Enter that account's password, scan the QR code with your authenticator app (or enter the displayed key manually), then enter the app's six-digit code to confirm. The QR code is generated locally by the app; the setup secret is not sent to a QR service. Repeat with the other demo accounts only if you want them protected too. Existing accounts and passwords are preserved.

When you first enable 2FA, the app creates its private encryption key automatically at `C:\xampp\apache\conf\cse1-totp.key`, outside the web root. No command-line setup, Apache configuration change, or restart is needed. Keep this key file private and backed up; enrolled authenticator secrets cannot be decrypted without it. If your XAMPP folder is elsewhere, configure `CSE1_TOTP_KEY_FILE` to a private path outside the web root before enabling 2FA. The optional `setup_totp_key.php` utility can create the key in advance and never displays or overwrites an existing key.

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

## Locked for next phase (not implemented yet)
- Bulk product/supplier import and export
- Advanced reporting and charts
- Admin user management (create/edit/delete users)
- More advanced audit trail and archive features
- Full soft-deactivation cleanup and role-specific permissions polish

## Notes
This is intentionally limited to 50% of the full inventory system so it can be explained quickly during class without becoming too large or complex.

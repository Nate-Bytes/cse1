# Minimal PHP Printing Press Inventory System (Phase 1 / 50%)

This project is a small PHP + MySQL inventory app for a printing press business. It is intentionally compact and server-rendered using plain PHP to keep it easy to explain in class.

## Included in this phase
- MySQL schema and sample data for a print shop
- Login/logout with role checks
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
4. Open `http://localhost/cse1/index.php` in the browser.

## Locked for next phase (not implemented yet)
- Bulk product/supplier import and export
- Advanced reporting and charts
- Admin user management (create/edit/delete users)
- More advanced audit trail and archive features
- Full soft-deactivation cleanup and role-specific permissions polish

## Notes
This is intentionally limited to 50% of the full inventory system so it can be explained quickly during class without becoming too large or complex.

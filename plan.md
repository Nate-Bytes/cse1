## Plan: Minimal PHP Inventory System

**TL;DR:** Build a compact, server-rendered plain-PHP inventory app for a class presentation. The workspace `c:\xampp\htdocs\cse1` is empty, so there is no existing project or convention to preserve. Keep the implementation to the four requested tables and core workflows.

**Steps**
1. Check XAMPP's PHP/MySQL versions and choose compatible syntax. Set up a small project with `index.php`, a PDO connection include, shared session/auth helpers, and a few feature pages.
2. Add an importable SQL file defining `USERS`, `SUPPLIERS`, `PRODUCTS`, and `TRANSACTION_HISTORY`, plus demo users, suppliers, and products. Store demo credentials as password hashes and document them for the presentation.
3. Implement login/logout and server-side role checks. Admin has full access; Manager manages products/suppliers and stock and can view dashboard/history; Staff can view products/dashboard and post stock movements but cannot edit the catalog.
4. Implement supplier and product listing/search, add/edit forms, and soft deactivation so related inventory/history remains intact.
5. Implement stock-in/out posting: validate positive quantities, update product quantity and insert history with actor, movement type, and before/after quantities in one database transaction. Prevent negative stock and guard concurrent updates from producing mismatched balances/history.
6. Add a compact dashboard showing in-stock, low-stock, and out-of-stock counts and a low-stock product list. Include a simple transaction-history list.
7. Verify in XAMPP by importing the SQL and exercising authentication, role boundaries, catalog changes/search/deactivation, both stock directions, insufficient-stock rejection, history values, and dashboard counts.

**Relevant files**
- `index.php` — minimal entry point and navigation.
- New shared PHP includes and feature pages — PDO setup, authentication/authorization, dashboard, products, suppliers, and stock/history workflows.
- New SQL schema/seed file — exact requested tables and sample data.

**Verification**
1. Confirm local PHP/MySQL versions and compatibility.
2. Import the SQL file into a clean XAMPP database and log in with each seeded role.
3. Confirm forbidden actions are denied server-side for each role, not merely hidden in the UI.
4. Confirm stock changes and history commit together; an insufficient-stock attempt leaves both unchanged.
5. Confirm dashboard counts and low-stock list match seeded and updated product quantities.

**Decisions**
- Use plain PHP, PDO prepared statements, hashed passwords, and server-side sessions; avoid adding a framework.
- Use the exact requested uppercase table names.
- Use soft deactivation for products and suppliers.
- Chosen role permissions were confirmed: Admin full access; Manager catalog/stock/dashboard/history; Staff read-only catalog/dashboard plus stock posting.
- Keep scope to the requested class-demo workflows; exclude extra user administration screens, advanced reports, APIs, and deployment hardening.

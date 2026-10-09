<?php

function getDb(): PDO
{
    static $pdo = null;

    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $dsn = 'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4';

    $pdo = new PDO($dsn, DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);

    return $pdo;
}

function isLoggedIn(): bool
{
    return !empty($_SESSION['user_id']);
}

function requireLogin(): void
{
    if (!isLoggedIn()) {
        header('Location: index.php');
        exit;
    }
}

function requireRole(array $roles): void
{
    requireLogin();

    if (!in_array($_SESSION['user_role'], $roles, true)) {
        http_response_code(403);
        echo '<h2>Access denied</h2><p>You do not have permission to view this page.</p>';
        exit;
    }
}

function logoutUser(): void
{
    $_SESSION = [];
    session_destroy();
    header('Location: index.php');
    exit;
}

function e(string $value): string
{
    return htmlspecialchars($value ?? '', ENT_QUOTES, 'UTF-8');
}

function getUserByEmail(PDO $db, string $email): ?array
{
    $stmt = $db->prepare('SELECT * FROM USERS WHERE email = :email LIMIT 1');
    $stmt->execute(['email' => strtolower(trim($email))]);
    $user = $stmt->fetch();

    return $user ?: null;
}

function getSupplierOptions(PDO $db): array
{
    $stmt = $db->query('SELECT id, name FROM SUPPLIERS WHERE is_active = 1 ORDER BY name ASC');
    return $stmt->fetchAll();
}

function getDashboardStats(PDO $db): array
{
    $total = $db->query('SELECT COUNT(*) AS total FROM PRODUCTS WHERE is_active = 1')->fetch();
    $inStock = $db->query('SELECT COUNT(*) AS total FROM PRODUCTS WHERE is_active = 1 AND quantity > reorder_level')->fetch();
    $lowStock = $db->query('SELECT COUNT(*) AS total FROM PRODUCTS WHERE is_active = 1 AND quantity <= reorder_level AND quantity > 0')->fetch();
    $outOfStock = $db->query('SELECT COUNT(*) AS total FROM PRODUCTS WHERE is_active = 1 AND quantity = 0')->fetch();

    return [
        'total' => (int) ($total['total'] ?? 0),
        'in_stock' => (int) ($inStock['total'] ?? 0),
        'low_stock' => (int) ($lowStock['total'] ?? 0),
        'out_of_stock' => (int) ($outOfStock['total'] ?? 0),
    ];
}

function getLowStockList(PDO $db): array
{
    $stmt = $db->query(
        'SELECT p.id, p.name, p.quantity, p.reorder_level, s.name AS supplier_name ' .
        'FROM PRODUCTS p ' .
        'LEFT JOIN SUPPLIERS s ON s.id = p.supplier_id ' .
        'WHERE p.is_active = 1 AND p.quantity <= p.reorder_level AND p.quantity > 0 ' .
        'ORDER BY p.quantity ASC, p.name ASC LIMIT 10'
    );

    return $stmt->fetchAll();
}

function getRecentTransactions(PDO $db, int $limit = 8): array
{
    $stmt = $db->prepare(
        'SELECT th.*, p.name AS product_name, u.name AS user_name ' .
        'FROM TRANSACTION_HISTORY th ' .
        'LEFT JOIN PRODUCTS p ON p.id = th.product_id ' .
        'LEFT JOIN USERS u ON u.id = th.user_id ' .
        'ORDER BY th.created_at DESC LIMIT :limit'
    );
    $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
    $stmt->execute();

    return $stmt->fetchAll();
}

function renderNavbar(string $currentPage, array $user): string
{
    $nav = [
        'dashboard' => 'Dashboard',
        'products' => 'Products',
        'suppliers' => 'Suppliers',
        'stock' => 'Stock Movement',
    ];

    $html = '<nav class="nav">';
    foreach ($nav as $page => $label) {
        $active = $currentPage === $page ? ' active' : '';
        $html .= '<a class="nav-item' . $active . '" href="index.php?page=' . $page . '">' . $label . '</a>';
    }
    $html .= '<a class="nav-item danger" href="index.php?logout=1">Logout</a>';
    $html .= '<span class="user-pill">' . e($user['name']) . ' (' . e($user['role']) . ')</span>';
    $html .= '</nav>';

    return $html;
}

function renderLayout(string $title, string $content, string $currentPage, array $user): string
{
    return '
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>' . e($title) . '</title>
        <style>
            * { box-sizing: border-box; }
            body { font-family: Arial, sans-serif; background: #f3f4f6; margin: 0; color: #1f2937; }
            .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
            .nav { display: flex; flex-wrap: wrap; gap: 10px; padding: 14px 18px; background: #111827; color: white; border-radius: 12px; margin-bottom: 20px; }
            .nav-item { color: white; text-decoration: none; padding: 8px 12px; border-radius: 8px; }
            .nav-item.active { background: #2563eb; }
            .nav-item.danger { background: #b91c1c; }
            .user-pill { margin-left: auto; align-self: center; background: rgba(255,255,255,0.12); border-radius: 999px; padding: 8px 12px; font-size: 12px; }
            .card { background: white; border-radius: 12px; box-shadow: 0 1px 5px rgba(0,0,0,0.08); padding: 18px; margin-bottom: 20px; }
            .grid { display: grid; gap: 18px; }
            .two-col { grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); }
            .stat { background: #eff6ff; border-left: 5px solid #2563eb; padding: 16px; border-radius: 8px; }
            .stat h3 { margin: 0 0 8px; font-size: 14px; color: #374151; }
            .stat .value { font-size: 28px; font-weight: bold; }
            .notice { background: #fff7ed; border: 1px solid #fdba74; color: #9a4d00; padding: 12px 14px; border-radius: 8px; margin-bottom: 20px; }
            table { width: 100%; border-collapse: collapse; }
            th, td { border-bottom: 1px solid #e5e7eb; padding: 10px 8px; text-align: left; font-size: 14px; }
            th { background: #f9fafb; }
            .btn { display: inline-block; text-decoration: none; border: none; padding: 10px 14px; border-radius: 8px; cursor: pointer; background: #2563eb; color: white; }
            .btn.secondary { background: #4b5563; }
            .btn.warning { background: #d97706; }
            .btn.danger { background: #dc2626; }
            form { display: grid; gap: 12px; }
            .field { display: grid; gap: 6px; }
            .field input, .field select, .field textarea { width: 100%; padding: 10px 12px; border: 1px solid #d1d5db; border-radius: 8px; }
            .inline { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
            .alert { padding: 12px 14px; border-radius: 8px; margin-bottom: 16px; }
            .alert.success { background: #ecfdf5; color: #065f46; }
            .alert.error { background: #fef2f2; color: #991b1b; }
            .muted { color: #6b7280; }
            .status-badge { display: inline-block; padding: 4px 8px; border-radius: 999px; font-size: 12px; font-weight: bold; }
            .status-active { background: #dcfce7; color: #166534; }
            .status-inactive { background: #f3f4f6; color: #374151; }
            @media (max-width: 700px) { .user-pill { margin-left: 0; } }
        </style>
    </head>
    <body>
        <div class="container">
            ' . renderNavbar($currentPage, $user) . '
            ' . $content . '
        </div>
    </body>
    </html>';
}

function renderLoginPage(?string $message = null, ?string $error = null): string
{
    $html = '<div class="card" style="max-width: 420px; margin: 60px auto;">
        <h2>Inventory Login</h2>';

    if ($error) {
        $html .= '<div class="alert error">' . e($error) . '</div>';
    }

    if ($message) {
        $html .= '<div class="alert success">' . e($message) . '</div>';
    }

    $html .= '
        <form method="post">
            <div class="field">
                <label>Email</label>
                <input type="email" name="email" required placeholder="admin@demo.com" />
            </div>
            <div class="field">
                <label>Password</label>
                <input type="password" name="password" required placeholder="Enter password" />
            </div>
            <button type="submit" name="login" class="btn">Login</button>
        </form>
        <p class="muted">Demo accounts: admin@demo.com / admin123, manager@demo.com / manager123, staff@demo.com / staff123</p>
    </div>';

    return $html;
}

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

    ensureTotpSchema($pdo);

    return $pdo;
}

function ensureTotpSchema(PDO $db): void
{
    $columns = $db->query('SHOW COLUMNS FROM USERS')->fetchAll(PDO::FETCH_COLUMN);
    $required = [
        'totp_secret' => 'TEXT DEFAULT NULL',
        'totp_enabled' => 'TINYINT(1) NOT NULL DEFAULT 0',
        'totp_last_used' => 'BIGINT UNSIGNED DEFAULT NULL',
        'totp_failed_attempts' => 'TINYINT UNSIGNED NOT NULL DEFAULT 0',
        'totp_locked_until' => 'DATETIME DEFAULT NULL',
    ];

    if (count(array_diff(array_keys($required), $columns)) === 0) {
        return;
    }

    $lock = $db->query("SELECT GET_LOCK('cse1_totp_schema_migration', 10)")->fetchColumn();
    if ((int) $lock !== 1) {
        throw new RuntimeException('Could not acquire the database lock to prepare two-factor authentication.');
    }

    try {
        $columns = $db->query('SHOW COLUMNS FROM USERS')->fetchAll(PDO::FETCH_COLUMN);
        $additions = [];
        foreach ($required as $column => $definition) {
            if (!in_array($column, $columns, true)) {
                $additions[] = 'ADD COLUMN ' . $column . ' ' . $definition;
            }
        }

        if ($additions !== []) {
            $db->exec('ALTER TABLE USERS ' . implode(', ', $additions));
        }
    } finally {
        $db->query("SELECT RELEASE_LOCK('cse1_totp_schema_migration')");
    }
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

function csrfToken(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['csrf_token'];
}

function hasValidCsrfToken(): bool
{
    return isset($_POST['csrf_token'], $_SESSION['csrf_token'])
        && is_string($_POST['csrf_token'])
        && hash_equals($_SESSION['csrf_token'], $_POST['csrf_token']);
}

function totpEncryptionKey(): string
{
    if (!preg_match('/\A[a-f0-9]{64}\z/i', TOTP_ENCRYPTION_KEY)) {
        throw new RuntimeException('Generate the 2FA encryption key by running C:\\xampp\\php\\php.exe C:\\xampp\\htdocs\\cse1\\setup_totp_key.php.');
    }

    $key = hex2bin(TOTP_ENCRYPTION_KEY);
    if ($key === false) {
        throw new RuntimeException('CSE1_TOTP_ENCRYPTION_KEY is not a valid hex key.');
    }

    return $key;
}

function encryptTotpSecret(string $secret): string
{
    $nonce = random_bytes(12);
    $tag = '';
    $ciphertext = openssl_encrypt($secret, 'aes-256-gcm', totpEncryptionKey(), OPENSSL_RAW_DATA, $nonce, $tag);

    if ($ciphertext === false) {
        throw new RuntimeException('Could not encrypt the authenticator secret.');
    }

    return base64_encode($nonce . $tag . $ciphertext);
}

function decryptTotpSecret(string $encrypted): string
{
    $payload = base64_decode($encrypted, true);
    if ($payload === false || strlen($payload) < 29) {
        throw new RuntimeException('The saved authenticator secret is invalid.');
    }

    $secret = openssl_decrypt(
        substr($payload, 28),
        'aes-256-gcm',
        totpEncryptionKey(),
        OPENSSL_RAW_DATA,
        substr($payload, 0, 12),
        substr($payload, 12, 16)
    );

    if ($secret === false) {
        throw new RuntimeException('Could not decrypt the authenticator secret. Check CSE1_TOTP_ENCRYPTION_KEY.');
    }

    return $secret;
}

function base32Encode(string $value): string
{
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = '';
    foreach (str_split($value) as $character) {
        $bits .= str_pad(decbin(ord($character)), 8, '0', STR_PAD_LEFT);
    }

    $encoded = '';
    foreach (str_split($bits, 5) as $chunk) {
        if (strlen($chunk) < 5) {
            $chunk = str_pad($chunk, 5, '0');
        }
        $encoded .= $alphabet[bindec($chunk)];
    }

    return $encoded;
}

function base32Decode(string $value): string
{
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = '';
    foreach (str_split(strtoupper(rtrim($value, '='))) as $character) {
        $position = strpos($alphabet, $character);
        if ($position === false) {
            throw new RuntimeException('The saved authenticator secret is invalid.');
        }
        $bits .= str_pad(decbin($position), 5, '0', STR_PAD_LEFT);
    }

    $decoded = '';
    foreach (str_split($bits, 8) as $byte) {
        if (strlen($byte) === 8) {
            $decoded .= chr(bindec($byte));
        }
    }

    return $decoded;
}

function generateTotpSecret(): string
{
    return base32Encode(random_bytes(20));
}

function verifyTotpCode(string $secret, string $code, ?int $lastUsedCounter = null): ?int
{
    if (!preg_match('/^\d{6}$/', $code)) {
        return null;
    }

    $key = base32Decode($secret);
    $currentCounter = (int) floor(time() / 30);
    for ($counter = $currentCounter - 1; $counter <= $currentCounter + 1; $counter++) {
        if ($counter < 0 || ($lastUsedCounter !== null && $counter <= $lastUsedCounter)) {
            continue;
        }

        $binaryCounter = pack('N2', ($counter >> 32) & 0xffffffff, $counter & 0xffffffff);
        $hash = hash_hmac('sha1', $binaryCounter, $key, true);
        $offset = ord($hash[19]) & 0x0f;
        $number = unpack('N', substr($hash, $offset, 4))[1] & 0x7fffffff;
        if (hash_equals(str_pad((string) ($number % 1000000), 6, '0', STR_PAD_LEFT), $code)) {
            return $counter;
        }
    }

    return null;
}

function completeLogin(array $user): void
{
    session_regenerate_id(true);
    unset(
        $_SESSION['csrf_token'],
        $_SESSION['pending_2fa_user_id'],
        $_SESSION['pending_2fa_attempts'],
        $_SESSION['totp_setup_secret']
    );
    $_SESSION['user_id'] = (int) $user['id'];
    $_SESSION['user_name'] = $user['name'];
    $_SESSION['user_role'] = $user['role'];
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

function getUserById(PDO $db, int $id): ?array
{
    $stmt = $db->prepare('SELECT * FROM USERS WHERE id = :id LIMIT 1');
    $stmt->execute(['id' => $id]);
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
        'security' => 'Security',
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
            .qr-code { width: fit-content; max-width: 100%; margin: 16px 0; padding: 12px; background: white; border: 1px solid #e5e7eb; border-radius: 8px; }
            .qr-code svg { display: block; width: min(100%, 320px); height: auto; }
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
            <input type="hidden" name="csrf_token" value="' . e(csrfToken()) . '" />
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

function renderTotpLoginPage(?string $error = null): string
{
    $html = '<div class="card" style="max-width: 420px; margin: 60px auto;">
        <h2>Two-factor verification</h2>
        <p>Enter the six-digit code from your authenticator app.</p>';

    if ($error) {
        $html .= '<div class="alert error">' . e($error) . '</div>';
    }

    $html .= '<form method="post">
        <input type="hidden" name="csrf_token" value="' . e(csrfToken()) . '" />
        <div class="field"><label for="totp_code">Authenticator code</label>
        <input id="totp_code" type="text" name="totp_code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required autofocus></div>
        <button type="submit" name="verify_2fa" class="btn">Verify</button>
        <a href="index.php?cancel_2fa=1" class="btn secondary">Cancel</a>
    </form></div>';

    return $html;
}

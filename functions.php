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
    ensureAuditSchema($pdo);

    return $pdo;
}

function ensureAuditSchema(PDO $db): void
{
    $db->exec(
        'CREATE TABLE IF NOT EXISTS AUDIT_LOG (' .
        'id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, ' .
        'actor_user_id INT DEFAULT NULL, ' .
        'action VARCHAR(50) NOT NULL, ' .
        'entity_type VARCHAR(50) NOT NULL, ' .
        'entity_id BIGINT DEFAULT NULL, ' .
        'summary VARCHAR(255) NOT NULL, ' .
        'details TEXT DEFAULT NULL, ' .
        'created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, ' .
        'INDEX idx_audit_created (created_at), ' .
        'INDEX idx_audit_entity (entity_type, entity_id), ' .
        'CONSTRAINT fk_audit_actor FOREIGN KEY (actor_user_id) REFERENCES USERS(id) ON DELETE SET NULL' .
        ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
    );
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

function e(?string $value): string
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

function getSupplierOptions(PDO $db, ?int $includeId = null): array
{
    // Active suppliers, plus the one a product already uses (even if inactive),
    // so editing a product never silently switches its supplier.
    $stmt = $db->prepare('SELECT id, name, is_active FROM SUPPLIERS WHERE is_active = 1 OR id = :include_id ORDER BY name ASC');
    $stmt->bindValue(':include_id', $includeId ?? 0, PDO::PARAM_INT);
    $stmt->execute();
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
        'ORDER BY th.created_at DESC, th.id DESC LIMIT :limit'
    );
    $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
    $stmt->execute();

    return $stmt->fetchAll();
}

function writeAudit(PDO $db, string $action, string $entityType, ?int $entityId, string $summary, array $details = []): void
{
    $stmt = $db->prepare(
        'INSERT INTO AUDIT_LOG (actor_user_id, action, entity_type, entity_id, summary, details) ' .
        'VALUES (:actor_user_id, :action, :entity_type, :entity_id, :summary, :details)'
    );
    $stmt->execute([
        'actor_user_id' => $_SESSION['user_id'] ?? null,
        'action' => $action,
        'entity_type' => $entityType,
        'entity_id' => $entityId,
        'summary' => mb_substr($summary, 0, 255),
        'details' => $details === [] ? null : json_encode($details, JSON_THROW_ON_ERROR),
    ]);
}

function getStockMovementReport(PDO $db, string $startDate, string $endDate): array
{
    $stmt = $db->prepare(
        'SELECT DATE_FORMAT(created_at, \'%Y-%m\') AS month, type, SUM(quantity) AS total_quantity, COUNT(*) AS movement_count ' .
        'FROM TRANSACTION_HISTORY WHERE created_at >= :start_date AND created_at < DATE_ADD(:end_date, INTERVAL 1 DAY) ' .
        'GROUP BY DATE_FORMAT(created_at, \'%Y-%m\'), type ORDER BY month ASC'
    );
    $stmt->execute(['start_date' => $startDate, 'end_date' => $endDate]);
    return $stmt->fetchAll();
}

function getAuditEntries(PDO $db, int $limit = 100): array
{
    $stmt = $db->prepare(
        'SELECT a.*, u.name AS actor_name FROM AUDIT_LOG a ' .
        'LEFT JOIN USERS u ON u.id = a.actor_user_id ' .
        'ORDER BY a.created_at DESC, a.id DESC LIMIT :limit'
    );
    $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
    $stmt->execute();
    return $stmt->fetchAll();
}

function exportCatalogCsv(PDO $db, string $kind): never
{
    $kind = $kind === 'suppliers' ? 'suppliers' : 'products';
    writeAudit($db, 'export', $kind, null, 'Exported active ' . $kind);
    $filename = $kind . '-' . date('Y-m-d') . '.csv';
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    $output = fopen('php://output', 'wb');

    if ($kind === 'products') {
        writeCatalogCsvRow($output, ['sku', 'name', 'supplier', 'reorder_level', 'opening_quantity']);
        $rows = $db->query(
            'SELECT p.sku, p.name, s.name AS supplier, p.reorder_level, p.quantity AS opening_quantity ' .
            'FROM PRODUCTS p JOIN SUPPLIERS s ON s.id = p.supplier_id ' .
            'WHERE p.is_active = 1 ORDER BY p.name'
        );
    } else {
        writeCatalogCsvRow($output, ['name', 'contact_person', 'phone', 'email']);
        $rows = $db->query('SELECT name, contact_person, phone, email FROM SUPPLIERS WHERE is_active = 1 ORDER BY name');
    }

    while ($row = $rows->fetch(PDO::FETCH_NUM)) {
        writeCatalogCsvRow($output, $row);
    }

    fclose($output);
    exit;
}

function writeCatalogCsvRow($output, array $row): void
{
    $safeRow = array_map(static function ($value) {
        if (is_string($value) && preg_match('/^[=+\-@\t\r]/', $value)) {
            return "'" . $value;
        }
        return $value;
    }, $row);
    fputcsv($output, $safeRow);
}

function importCatalogCsv(PDO $db, string $kind, string $filePath, int $actorId): array
{
    if (!is_file($filePath) || filesize($filePath) > 2_000_000) {
        throw new RuntimeException('Choose a CSV file smaller than 2 MB.');
    }

    $input = fopen($filePath, 'rb');
    if ($input === false) {
        throw new RuntimeException('The uploaded CSV could not be opened.');
    }

    $expected = $kind === 'products'
        ? ['sku', 'name', 'supplier', 'reorder_level', 'opening_quantity']
        : ['name', 'contact_person', 'phone', 'email'];
    $header = fgetcsv($input);
    if (!is_array($header)) {
        fclose($input);
        throw new RuntimeException('The CSV file is empty.');
    }
    if (isset($header[0])) {
        $header[0] = preg_replace('/^\xEF\xBB\xBF/', '', (string) $header[0]);
    }
    $header = array_map(static fn ($value): string => strtolower(trim((string) $value)), $header);
    if ($header !== $expected) {
        fclose($input);
        throw new RuntimeException('CSV columns must be: ' . implode(', ', $expected) . '.');
    }

    $db->beginTransaction();
    $created = 0;
    $updated = 0;
    $rowNumber = 1;

    try {
        while (($values = fgetcsv($input)) !== false) {
            $rowNumber++;
            if ($values === [null] || $values === []) {
                continue;
            }
            if ($rowNumber > 1001) {
                throw new RuntimeException('CSV imports are limited to 1,000 data rows.');
            }
            if (count($values) !== count($expected)) {
                throw new RuntimeException('Row ' . $rowNumber . ' has the wrong number of columns.');
            }

            $row = array_combine($expected, array_map(static fn ($value): string => trim((string) $value), $values));
            if ($kind === 'suppliers') {
                if ($row['name'] === '' || mb_strlen($row['name']) > 150 || mb_strlen($row['contact_person']) > 100 || mb_strlen($row['phone']) > 30 || mb_strlen($row['email']) > 100) {
                    throw new RuntimeException('Row ' . $rowNumber . ' has a missing or oversized supplier field.');
                }
                if ($row['email'] !== '' && !filter_var($row['email'], FILTER_VALIDATE_EMAIL)) {
                    throw new RuntimeException('Row ' . $rowNumber . ' has an invalid supplier email.');
                }

                $find = $db->prepare('SELECT id FROM SUPPLIERS WHERE name = :name ORDER BY id LIMIT 1 FOR UPDATE');
                $find->execute(['name' => $row['name']]);
                $supplierId = $find->fetchColumn();
                if ($supplierId !== false) {
                    $save = $db->prepare('UPDATE SUPPLIERS SET contact_person = :contact, phone = :phone, email = :email WHERE id = :id');
                    $save->execute([
                        'contact' => $row['contact_person'] !== '' ? $row['contact_person'] : null,
                        'phone' => $row['phone'] !== '' ? $row['phone'] : null,
                        'email' => $row['email'] !== '' ? $row['email'] : null,
                        'id' => $supplierId,
                    ]);
                    $updated++;
                } else {
                    $save = $db->prepare('INSERT INTO SUPPLIERS (name, contact_person, phone, email) VALUES (:name, :contact, :phone, :email)');
                    $save->execute([
                        'name' => $row['name'],
                        'contact' => $row['contact_person'] !== '' ? $row['contact_person'] : null,
                        'phone' => $row['phone'] !== '' ? $row['phone'] : null,
                        'email' => $row['email'] !== '' ? $row['email'] : null,
                    ]);
                    $created++;
                }
                continue;
            }

            if ($row['sku'] === '' || mb_strlen($row['sku']) > 100 || $row['name'] === '' || mb_strlen($row['name']) > 150 || $row['supplier'] === '') {
                throw new RuntimeException('Row ' . $rowNumber . ' has a missing or oversized product field.');
            }
            $reorderLevel = filter_var($row['reorder_level'], FILTER_VALIDATE_INT);
            $openingQuantity = filter_var($row['opening_quantity'], FILTER_VALIDATE_INT);
            if ($reorderLevel === false || $reorderLevel < 0 || $openingQuantity === false || $openingQuantity < 0) {
                throw new RuntimeException('Row ' . $rowNumber . ' must have nonnegative whole-number stock values.');
            }

            $findSupplier = $db->prepare('SELECT id FROM SUPPLIERS WHERE name = :name AND is_active = 1 LIMIT 1');
            $findSupplier->execute(['name' => $row['supplier']]);
            $supplierId = $findSupplier->fetchColumn();
            if ($supplierId === false) {
                throw new RuntimeException('Row ' . $rowNumber . ' references an unknown or inactive supplier.');
            }

            $findProduct = $db->prepare('SELECT id, is_active FROM PRODUCTS WHERE sku = :sku FOR UPDATE');
            $findProduct->execute(['sku' => $row['sku']]);
            $product = $findProduct->fetch();
            if ($product && (int) $product['is_active'] !== 1) {
                throw new RuntimeException('Row ' . $rowNumber . ' uses archived SKU ' . $row['sku'] . '. Reactivate it before importing.');
            }

            if ($product) {
                $save = $db->prepare('UPDATE PRODUCTS SET supplier_id = :supplier_id, name = :name, reorder_level = :reorder_level WHERE id = :id');
                $save->execute(['supplier_id' => $supplierId, 'name' => $row['name'], 'reorder_level' => $reorderLevel, 'id' => $product['id']]);
                $updated++;
            } else {
                $save = $db->prepare('INSERT INTO PRODUCTS (supplier_id, name, sku, quantity, reorder_level, is_active) VALUES (:supplier_id, :name, :sku, :quantity, :reorder_level, 1)');
                $save->execute([
                    'supplier_id' => $supplierId,
                    'name' => $row['name'],
                    'sku' => $row['sku'],
                    'quantity' => $openingQuantity,
                    'reorder_level' => $reorderLevel,
                ]);
                $productId = (int) $db->lastInsertId();
                if ($openingQuantity > 0) {
                    $opening = $db->prepare(
                        'INSERT INTO TRANSACTION_HISTORY (product_id, type, quantity, before_quantity, after_quantity, notes, user_id) ' .
                        'VALUES (:product_id, \'IN\', :quantity, 0, :quantity, \'CSV opening balance\', :user_id)'
                    );
                    $opening->execute(['product_id' => $productId, 'quantity' => $openingQuantity, 'user_id' => $actorId]);
                }
                $created++;
            }
        }

        if ($created + $updated === 0) {
            throw new RuntimeException('The CSV contains no data rows.');
        }
        writeAudit($db, 'import', $kind, null, 'Imported ' . ($created + $updated) . ' ' . $kind, ['created' => $created, 'updated' => $updated]);
        $db->commit();
    } catch (Throwable $ex) {
        if ($db->inTransaction()) {
            $db->rollBack();
        }
        fclose($input);
        throw $ex;
    }

    fclose($input);
    return ['created' => $created, 'updated' => $updated];
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

    $role = $user['role'] ?? '';
    if (!in_array($role, ['Admin', 'Manager'], true)) {
        unset($nav['suppliers']);
    }
    if (in_array($role, ['Admin', 'Manager'], true)) {
        $nav['reports'] = 'Reports';
    }
    if ($role === 'Admin') {
        $nav['audit'] = 'Audit Log';
        $nav['users'] = 'Users';
    }

    $html = '<aside class="sidebar"><a class="brand" href="index.php?page=dashboard"><span class="brand-mark" aria-hidden="true"><i></i><i></i><i></i><i></i></span><span class="brand-copy"><strong>Printing press</strong><small>Production stock</small></span></a><p class="sidebar-label">WORKSPACE</p><nav class="nav-links" aria-label="Main navigation">';
    foreach ($nav as $page => $label) {
        $active = $currentPage === $page ? ' active' : '';
        $html .= '<a class="nav-item' . $active . '" href="index.php?page=' . $page . '"' . ($currentPage === $page ? ' aria-current="page"' : '') . '>' . $label . '</a>';
    }
    $html .= '</nav><div class="sidebar-bottom"><div class="account-chip"><span class="account-initial">' . e(mb_strtoupper(mb_substr($user['name'] ?? '', 0, 1))) . '</span><span class="account-copy"><strong>' . e($user['name'] ?? '') . '</strong><small>' . e($user['role'] ?? '') . '</small></span></div><a class="signout-link" href="index.php?logout=1">Sign out <span aria-hidden="true">↗</span></a></div></aside>';

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
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Barlow+Condensed:wght@500;600;700&family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
        <link rel="stylesheet" href="assets/css/app.css" />
    </head>
    <body>
        <div class="app-shell">' . renderNavbar($currentPage, $user) . '<main class="workspace"><div class="workspace-bar"><span><i></i> PRINT FLOOR / STOCK CONTROL</span><time>' . e(date('D, d M Y')) . '</time></div><div class="container">' . $content . '</div></main></div>
    </body>
    </html>';
}

function renderAuthShell(string $title, string $content): string
{
    return '<!doctype html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>' . e($title) . ' | Printing press</title><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Barlow+Condensed:wght@500;600;700&family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap" rel="stylesheet"><link rel="stylesheet" href="assets/css/app.css"></head><body class="auth-body"><main class="auth-shell"><aside class="auth-story"><a class="brand brand-light" href="index.php"><span class="brand-mark" aria-hidden="true"><i></i><i></i><i></i><i></i></span><span class="brand-copy"><strong>Printing press</strong><small>Production stock</small></span></a><div class="auth-story-copy"><p class="eyebrow">PRINT SHOP / STOCK DESK</p><h1>Keep every press run moving.</h1><p>Paper, ink, plates, and finishing supplies, all accounted for.</p><div class="print-swatches" aria-hidden="true"><span></span><span></span><span></span><span></span></div></div><p class="auth-footnote">CSE1 inventory demo</p></aside><section class="auth-main"><div class="auth-panel"><p class="eyebrow">' . e($title) . '</p>' . $content . '</div></section></main></body></html>';
}

function renderLoginPage(?string $message = null, ?string $error = null): string
{
    $html = '<h2>Welcome back.</h2><p class="auth-subtitle">Sign in to the stock desk.</p>';

    if ($error) {
        $html .= '<div class="alert error">' . e($error) . '</div>';
    }

    if ($message) {
        $html .= '<div class="alert success">' . e($message) . '</div>';
    }

    $html .= '
        <form method="post" class="auth-form">
            <input type="hidden" name="csrf_token" value="' . e(csrfToken()) . '" />
            <div class="field">
                <label for="login-email">Email</label>
                <input id="login-email" type="email" name="email" required placeholder="admin@demo.com" autocomplete="username" />
            </div>
            <div class="field">
                <label for="login-password">Password</label>
                <input id="login-password" type="password" name="password" required placeholder="Enter password" autocomplete="current-password" />
            </div>
            <button type="submit" name="login" class="btn">Login</button>
        </form>
        <details class="demo-accounts"><summary>Demo accounts</summary><p>Admin: admin@demo.com / admin123<br>Manager: manager@demo.com / manager123<br>Staff: staff@demo.com / staff123</p></details>';

    return renderAuthShell('Sign in', $html);
}

function renderTotpLoginPage(?string $error = null): string
{
    $html = '<h2>Verify it’s you.</h2><p class="auth-subtitle">Enter the six-digit code from your authenticator app.</p>';

    if ($error) {
        $html .= '<div class="alert error">' . e($error) . '</div>';
    }

    $html .= '<form method="post" class="auth-form">
        <input type="hidden" name="csrf_token" value="' . e(csrfToken()) . '" />
        <div class="field"><label for="totp_code">Authenticator code</label>
        <input id="totp_code" type="text" name="totp_code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required autofocus></div>
        <div class="inline"><button type="submit" name="verify_2fa" class="btn">Verify code</button>
        <a href="index.php?cancel_2fa=1" class="btn secondary">Cancel</a></div>
    </form>';

    return renderAuthShell('Two-factor verification', $html);
}

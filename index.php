<?php
session_start();

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/functions.php';

$db = getDb();

if (isset($_GET['logout'])) {
    logoutUser();
}

$error = null;
$message = null;
$page = $_GET['page'] ?? 'dashboard';

if (!isLoggedIn()) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
        if (!hasValidCsrfToken()) {
            $error = 'Your session expired. Please try again.';
        } else {
            $email = trim((string) ($_POST['email'] ?? ''));
            $password = (string) ($_POST['password'] ?? '');
            $user = getUserByEmail($db, $email);

            if ($user && password_verify($password, $user['password_hash']) && (int) $user['is_active'] === 1) {
                if ((int) $user['totp_enabled'] === 1) {
                    if (!empty($user['totp_locked_until']) && strtotime($user['totp_locked_until']) > time()) {
                        $error = 'Too many incorrect codes. Please wait five minutes before trying again.';
                    } else {
                        if (!empty($user['totp_locked_until'])) {
                            $reset = $db->prepare('UPDATE USERS SET totp_failed_attempts = 0, totp_locked_until = NULL WHERE id = :id');
                            $reset->execute(['id' => $user['id']]);
                        }
                        session_regenerate_id(true);
                        unset($_SESSION['csrf_token']);
                        $_SESSION['pending_2fa_user_id'] = (int) $user['id'];
                        $_SESSION['pending_2fa_attempts'] = 0;
                    }
                } else {
                    completeLogin($user);
                    header('Location: index.php?page=dashboard');
                    exit;
                }
            } else {
                $error = 'Invalid email or password.';
            }
        }

    } elseif ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['verify_2fa'])) {
        if (!hasValidCsrfToken()) {
            $error = 'Your session expired. Please sign in again.';
            unset($_SESSION['pending_2fa_user_id'], $_SESSION['pending_2fa_attempts']);
        } elseif (!empty($_SESSION['pending_2fa_user_id'])) {
            $user = getUserById($db, (int) $_SESSION['pending_2fa_user_id']);
            if (!$user || (int) $user['is_active'] !== 1 || (int) $user['totp_enabled'] !== 1) {
                unset($_SESSION['pending_2fa_user_id'], $_SESSION['pending_2fa_attempts']);
                $error = 'Sign-in could not be verified. Please sign in again.';
            } elseif (!empty($user['totp_locked_until']) && strtotime($user['totp_locked_until']) > time()) {
                unset($_SESSION['pending_2fa_user_id'], $_SESSION['pending_2fa_attempts']);
                $error = 'Too many incorrect codes. Please wait five minutes before trying again.';
            } elseif (empty($user['totp_secret'])) {
                unset($_SESSION['pending_2fa_user_id'], $_SESSION['pending_2fa_attempts']);
                $error = 'Two-factor sign-in is not configured correctly. Contact the system administrator.';
            } else {
                try {
                    $secret = decryptTotpSecret($user['totp_secret']);
                    $lastCounter = $user['totp_last_used'] === null ? null : (int) $user['totp_last_used'];
                    $counter = verifyTotpCode($secret, trim((string) ($_POST['totp_code'] ?? '')), $lastCounter);
                } catch (RuntimeException $e) {
                    $counter = null;
                    $error = $e->getMessage();
                }

                if ($counter !== null) {
                    $update = $db->prepare(
                        'UPDATE USERS SET totp_last_used = :counter, totp_failed_attempts = 0, totp_locked_until = NULL ' .
                        'WHERE id = :id AND totp_enabled = 1 AND (totp_last_used IS NULL OR totp_last_used < :previous_counter)'
                    );
                    $update->execute([
                        'counter' => $counter,
                        'id' => $user['id'],
                        'previous_counter' => $counter,
                    ]);

                    if ($update->rowCount() === 1) {
                        completeLogin($user);
                        header('Location: index.php?page=dashboard');
                        exit;
                    }
                    $error = 'That code has already been used. Enter the next code from your authenticator app.';
                }

                if ($counter === null || $update->rowCount() !== 1) {
                    if ($error === null) {
                        $recordFailure = $db->prepare(
                            'UPDATE USERS SET totp_failed_attempts = totp_failed_attempts + 1, ' .
                            'totp_locked_until = CASE WHEN totp_failed_attempts + 1 >= 5 ' .
                            'THEN DATE_ADD(NOW(), INTERVAL 5 MINUTE) ELSE NULL END WHERE id = :id'
                        );
                        $recordFailure->execute(['id' => $user['id']]);
                        $status = getUserById($db, (int) $user['id']);
                        $attempts = (int) $status['totp_failed_attempts'];
                        $error = $attempts >= 5
                            ? 'Too many incorrect codes. Please wait five minutes before trying again.'
                            : 'The authenticator code is invalid or expired.';
                        if ($attempts >= 5) {
                            unset($_SESSION['pending_2fa_user_id'], $_SESSION['pending_2fa_attempts']);
                        }
                    }
                }
            }
        } else {
            $error = 'Sign-in session expired. Please enter your email and password again.';
        }
    } elseif (isset($_GET['cancel_2fa'])) {
        unset($_SESSION['pending_2fa_user_id'], $_SESSION['pending_2fa_attempts']);
        header('Location: index.php');
        exit;
    }

    if (!empty($_SESSION['pending_2fa_user_id'])) {
        echo renderTotpLoginPage($error);
        exit;
    }
    echo renderLoginPage($message, $error);
    exit;
}

requireLogin();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['begin_totp_setup'])) {
    if (!hasValidCsrfToken()) {
        $error = 'Your session expired. Reload this page and try again.';
    } else {
        $user = getUserById($db, (int) $_SESSION['user_id']);
        if (!$user || !password_verify((string) ($_POST['current_password'] ?? ''), $user['password_hash'])) {
            $error = 'Enter your current password to set up 2FA.';
        } elseif ((int) $user['totp_enabled'] === 1) {
            $error = 'Two-factor authentication is already enabled.';
        } else {
            try {
                totpEncryptionKey();
                $_SESSION['totp_setup_secret'] = generateTotpSecret();
                $_SESSION['totp_setup_attempts'] = 0;
                $message = 'Add the secret to your authenticator app, then enter its current six-digit code below.';
            } catch (RuntimeException $e) {
                $error = $e->getMessage();
            }
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['confirm_totp_setup'])) {
    if (!hasValidCsrfToken()) {
        $error = 'Your session expired. Reload this page and try again.';
    } elseif (empty($_SESSION['totp_setup_secret'])) {
        $error = 'Start 2FA setup again before confirming a code.';
    } else {
        $secret = (string) $_SESSION['totp_setup_secret'];
        $counter = verifyTotpCode($secret, trim((string) ($_POST['totp_code'] ?? '')));
        if ($counter === null) {
            $_SESSION['totp_setup_attempts'] = (int) ($_SESSION['totp_setup_attempts'] ?? 0) + 1;
            $error = 'The authenticator code is invalid or expired.';
            if ($_SESSION['totp_setup_attempts'] >= 5) {
                unset($_SESSION['totp_setup_secret'], $_SESSION['totp_setup_attempts']);
                $error = 'Too many incorrect codes. Start 2FA setup again.';
            }
        } else {
            try {
                $encryptedSecret = encryptTotpSecret($secret);
            } catch (RuntimeException $e) {
                $error = $e->getMessage();
                $encryptedSecret = null;
            }

            if ($encryptedSecret !== null) {
                $save = $db->prepare(
                    'UPDATE USERS SET totp_secret = :secret, totp_enabled = 1, totp_last_used = :counter, ' .
                    'totp_failed_attempts = 0, totp_locked_until = NULL WHERE id = :id AND totp_enabled = 0'
                );
                $save->execute([
                    'secret' => $encryptedSecret,
                    'counter' => $counter,
                    'id' => $_SESSION['user_id'],
                ]);
                if ($save->rowCount() === 1) {
                    unset($_SESSION['totp_setup_secret'], $_SESSION['totp_setup_attempts']);
                    $message = 'Two-factor authentication is now enabled for this account.';
                } else {
                    $error = '2FA could not be enabled. Reload the page and check your account status.';
                }
            }
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['disable_totp'])) {
    if (!hasValidCsrfToken()) {
        $error = 'Your session expired. Reload this page and try again.';
    } else {
        $user = getUserById($db, (int) $_SESSION['user_id']);
        if (!$user || !password_verify((string) ($_POST['current_password'] ?? ''), $user['password_hash'])) {
            $error = 'Enter your current password and authenticator code to turn off 2FA.';
        } elseif ((int) $user['totp_enabled'] !== 1) {
            $error = 'Two-factor authentication is not enabled.';
        } elseif (empty($user['totp_secret'])) {
            $error = 'Two-factor authentication is not configured correctly. Contact the system administrator.';
        } else {
            try {
                $secret = decryptTotpSecret($user['totp_secret']);
                $lastCounter = $user['totp_last_used'] === null ? null : (int) $user['totp_last_used'];
                $counter = verifyTotpCode($secret, trim((string) ($_POST['totp_code'] ?? '')), $lastCounter);
                if ($counter === null) {
                    $error = 'The authenticator code is invalid or expired.';
                } else {
                    $disable = $db->prepare(
                        'UPDATE USERS SET totp_secret = NULL, totp_enabled = 0, totp_last_used = NULL, ' .
                        'totp_failed_attempts = 0, totp_locked_until = NULL WHERE id = :id AND totp_enabled = 1'
                    );
                    $disable->execute(['id' => $user['id']]);
                    $message = 'Two-factor authentication has been turned off.';
                }
            } catch (RuntimeException $e) {
                $error = $e->getMessage();
            }
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_product'])) {
    $id = isset($_POST['id']) && $_POST['id'] !== '' ? (int) $_POST['id'] : null;
    $supplierId = (int) ($_POST['supplier_id'] ?? 0);
    $name = trim((string) ($_POST['name'] ?? ''));
    $sku = trim((string) ($_POST['sku'] ?? ''));
    $reorderLevel = (int) ($_POST['reorder_level'] ?? 0);
    $quantity = (int) ($_POST['quantity'] ?? 0);

    if ($supplierId > 0 && $name !== '' && $sku !== '') {
        if ($id) {
            $stmt = $db->prepare('UPDATE PRODUCTS SET supplier_id = :supplier_id, name = :name, sku = :sku, reorder_level = :reorder_level, quantity = :quantity WHERE id = :id');
            $stmt->execute([
                'supplier_id' => $supplierId,
                'name' => $name,
                'sku' => $sku,
                'reorder_level' => $reorderLevel,
                'quantity' => $quantity,
                'id' => $id,
            ]);
            $message = 'Product updated.';
        } else {
            $stmt = $db->prepare('INSERT INTO PRODUCTS (supplier_id, name, sku, quantity, reorder_level, is_active, created_at) VALUES (:supplier_id, :name, :sku, :quantity, :reorder_level, 1, NOW())');
            $stmt->execute([
                'supplier_id' => $supplierId,
                'name' => $name,
                'sku' => $sku,
                'quantity' => $quantity,
                'reorder_level' => $reorderLevel,
            ]);
            $message = 'Product added.';
        }
    } else {
        $error = 'Please complete all product fields.';
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['toggle_product'])) {
    $id = (int) ($_POST['product_id'] ?? 0);
    if ($id > 0) {
        $stmt = $db->prepare('UPDATE PRODUCTS SET is_active = 1 - is_active WHERE id = :id');
        $stmt->execute(['id' => $id]);
        $message = 'Product status changed.';
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_supplier'])) {
    $id = isset($_POST['id']) && $_POST['id'] !== '' ? (int) $_POST['id'] : null;
    $name = trim((string) ($_POST['name'] ?? ''));
    $contactPerson = trim((string) ($_POST['contact_person'] ?? ''));
    $phone = trim((string) ($_POST['phone'] ?? ''));
    $email = trim((string) ($_POST['email'] ?? ''));

    if ($name !== '') {
        if ($id) {
            $stmt = $db->prepare('UPDATE SUPPLIERS SET name = :name, contact_person = :contact_person, phone = :phone, email = :email WHERE id = :id');
            $stmt->execute([
                'name' => $name,
                'contact_person' => $contactPerson,
                'phone' => $phone,
                'email' => $email,
                'id' => $id,
            ]);
            $message = 'Supplier updated.';
        } else {
            $stmt = $db->prepare('INSERT INTO SUPPLIERS (name, contact_person, phone, email, is_active, created_at) VALUES (:name, :contact_person, :phone, :email, 1, NOW())');
            $stmt->execute([
                'name' => $name,
                'contact_person' => $contactPerson,
                'phone' => $phone,
                'email' => $email,
            ]);
            $message = 'Supplier added.';
        }
    } else {
        $error = 'Supplier name is required.';
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['toggle_supplier'])) {
    $id = (int) ($_POST['supplier_id'] ?? 0);
    if ($id > 0) {
        $stmt = $db->prepare('UPDATE SUPPLIERS SET is_active = 1 - is_active WHERE id = :id');
        $stmt->execute(['id' => $id]);
        $message = 'Supplier status changed.';
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['post_stock'])) {
    $productId = (int) ($_POST['product_id'] ?? 0);
    $type = strtoupper((string) ($_POST['type'] ?? ''));
    $quantity = (int) ($_POST['quantity'] ?? 0);
    $notes = trim((string) ($_POST['notes'] ?? ''));

    if ($productId <= 0 || !in_array($type, ['IN', 'OUT'], true) || $quantity <= 0) {
        $error = 'Please select a valid product, movement type, and quantity greater than zero.';
    } else {
        try {
            $db->beginTransaction();
            $sel = $db->prepare('SELECT quantity FROM PRODUCTS WHERE id = :id FOR UPDATE');
            $sel->execute(['id' => $productId]);
            $product = $sel->fetch();

            if (!$product) {
                throw new RuntimeException('Product not found.');
            }

            $before = (int) $product['quantity'];
            $after = $type === 'IN' ? $before + $quantity : $before - $quantity;

            if ($after < 0) {
                throw new RuntimeException('Stock out cannot result in negative quantity.');
            }

            $update = $db->prepare('UPDATE PRODUCTS SET quantity = :quantity WHERE id = :id');
            $update->execute([
                'quantity' => $after,
                'id' => $productId,
            ]);

            $ins = $db->prepare(
                'INSERT INTO TRANSACTION_HISTORY (product_id, type, quantity, before_quantity, after_quantity, notes, user_id, created_at) ' .
                'VALUES (:product_id, :type, :quantity, :before_quantity, :after_quantity, :notes, :user_id, NOW())'
            );
            $ins->execute([
                'product_id' => $productId,
                'type' => $type,
                'quantity' => $quantity,
                'before_quantity' => $before,
                'after_quantity' => $after,
                'notes' => $notes !== '' ? $notes : 'Manual stock movement',
                'user_id' => $_SESSION['user_id'],
            ]);

            $db->commit();
            $message = 'Stock movement recorded successfully.';
        } catch (Throwable $e) {
            $db->rollBack();
            $error = $e->getMessage();
        }
    }
}

if ($page === 'security') {
    $account = getUserById($db, (int) $_SESSION['user_id']);
    $twoFactorEnabled = $account && (int) $account['totp_enabled'] === 1;
    $content = '<div class="card"><h2>Account security</h2>';
    if ($message) { $content .= '<div class="alert success">' . e($message) . '</div>'; }
    if ($error) { $content .= '<div class="alert error">' . e($error) . '</div>'; }
    $content .= '<p>Two-factor authentication is optional. Turn it on for this account here; repeat these steps with each demo account you want to protect.</p>';

    if ($twoFactorEnabled) {
        $content .= '<p>Two-factor authentication is <strong>enabled</strong> for this account.</p>';
        $content .= '<h3>Turn off two-factor authentication</h3>';
        $content .= '<p class="muted">Confirm with your account password and a current authenticator code.</p>';
        $content .= '<form method="post">
            <input type="hidden" name="csrf_token" value="' . e(csrfToken()) . '">
            <div class="field"><label for="disable_password">Current password</label><input id="disable_password" type="password" name="current_password" required autocomplete="current-password"></div>
            <div class="field"><label for="disable_code">Authenticator code</label><input id="disable_code" type="text" name="totp_code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required autocomplete="one-time-code"></div>
            <button type="submit" name="disable_totp" class="btn danger">Turn off 2FA</button>
        </form>';
    } elseif (!empty($_SESSION['totp_setup_secret'])) {
        $secret = (string) $_SESSION['totp_setup_secret'];
        $label = rawurlencode('CSE1 Inventory:' . $account['email']);
        $otpauthUri = 'otpauth://totp/' . $label . '?secret=' . rawurlencode($secret) . '&issuer=CSE1%20Inventory&algorithm=SHA1&digits=6&period=30';
        $content .= '<p>Scan this QR code with your authenticator app. Keep it private; anyone who scans it can generate sign-in codes for your account.</p>
            <div id="totp-qr" class="qr-code" role="img" aria-label="Authenticator setup QR code" data-qr-value="' . e($otpauthUri) . '"></div>
            <p class="muted">If you cannot scan the QR code, choose manual setup in your authenticator app and enter these details:</p>
            <ul><li>Account: ' . e($account['email']) . '</li><li>Setup key: <code>' . e($secret) . '</code></li><li>Type: time-based (TOTP)</li></ul>
            <p id="totp-qr-error" class="alert error" hidden>The QR code could not be displayed. Use the setup key above instead.</p>
            <form method="post">
                <input type="hidden" name="csrf_token" value="' . e(csrfToken()) . '">
                <div class="field"><label for="setup_code">Verify setup with an authenticator code</label><input id="setup_code" type="text" name="totp_code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required autocomplete="one-time-code"></div>
                <button type="submit" name="confirm_totp_setup" class="btn">Verify and enable 2FA</button>
            </form>
            <script src="assets/vendor/qrcode.js"></script>
            <script src="assets/vendor/qrcode_UTF8.js"></script>
            <script>
                (function () {
                    var target = document.getElementById("totp-qr");
                    var fallback = document.getElementById("totp-qr-error");
                    try {
                        var qr = qrcode(0, "M");
                        qr.addData(target.getAttribute("data-qr-value"), "Byte");
                        qr.make();
                        target.innerHTML = qr.createSvgTag(5, 4);
                    } catch (error) {
                        fallback.hidden = false;
                    }
                }());
            </script>';
    } else {
        $content .= '<p>Two-factor authentication is <strong>off</strong> for this account.</p>';
        $content .= '<p>Use an authenticator app such as Google Authenticator, Microsoft Authenticator, or Authy. Setup requires your current password.</p>';
        $content .= '<form method="post">
            <input type="hidden" name="csrf_token" value="' . e(csrfToken()) . '">
            <div class="field"><label for="setup_password">Current password</label><input id="setup_password" type="password" name="current_password" required autocomplete="current-password"></div>
            <button type="submit" name="begin_totp_setup" class="btn">Enable 2FA for this account</button>
        </form>';
    }
    $content .= '</div>';
} elseif ($page === 'products') {
    $search = trim((string) ($_GET['q'] ?? ''));
    $query = 'SELECT p.*, s.name AS supplier_name FROM PRODUCTS p LEFT JOIN SUPPLIERS s ON s.id = p.supplier_id WHERE p.is_active = 1';
    $params = [];

    if ($search !== '') {
        $query .= ' AND (p.name LIKE :search OR p.sku LIKE :search OR s.name LIKE :search)';
        $params['search'] = '%' . $search . '%';
    }

    $query .= ' ORDER BY p.name ASC';
    $stmt = $db->prepare($query);
    $stmt->execute($params);
    $products = $stmt->fetchAll();

    $productId = isset($_GET['edit_product']) ? (int) $_GET['edit_product'] : 0;
    $editingProduct = null;
    if ($productId > 0) {
        $stmt = $db->prepare('SELECT * FROM PRODUCTS WHERE id = :id');
        $stmt->execute(['id' => $productId]);
        $editingProduct = $stmt->fetch();
    }

    $suppliers = getSupplierOptions($db);
    $content = '<div class="notice">Phase 1 (50% complete). Locked for next phase: bulk import/export, advanced reporting, and full user administration.</div>'; 
    $content .= '<div class="card"><h2>Products</h2>';
    if ($message) { $content .= '<div class="alert success">' . e($message) . '</div>'; }
    if ($error) { $content .= '<div class="alert error">' . e($error) . '</div>'; }
    $content .= '<div class="inline" style="margin-bottom: 16px;">';
    $content .= '<form method="get" style="display:flex; gap:10px; align-items:end; width: 100%;">';
    $content .= '<input type="hidden" name="page" value="products">';
    $content .= '<div class="field" style="flex:1; min-width:180px;"><label>Search</label><input type="text" name="q" value="' . e($search) . '" placeholder="Product or SKU"></div>';
    $content .= '<button class="btn secondary" type="submit">Search</button>';
    $content .= '</form>';
    $content .= '</div>';
    $content .= '<h3>' . ($editingProduct ? 'Edit Product' : 'Add Product') . '</h3>';
    $content .= '<form method="post"><input type="hidden" name="id" value="' . ($editingProduct['id'] ?? '') . '"><div class="grid two-col"><div class="field"><label>Supplier</label><select name="supplier_id" required>';
    foreach ($suppliers as $supplier) {
        $selected = ($editingProduct && (int) $editingProduct['supplier_id'] === (int) $supplier['id']) ? ' selected' : '';
        $content .= '<option value="' . (int) $supplier['id'] . '"' . $selected . '>' . e($supplier['name']) . '</option>';
    }
    $content .= '</select></div><div class="field"><label>Name</label><input type="text" name="name" value="' . e($editingProduct['name'] ?? '') . '" required></div><div class="field"><label>SKU</label><input type="text" name="sku" value="' . e($editingProduct['sku'] ?? '') . '" required></div><div class="field"><label>Reorder Level</label><input type="number" name="reorder_level" min="0" value="' . (int) ($editingProduct['reorder_level'] ?? 0) . '" required></div><div class="field"><label>Quantity</label><input type="number" name="quantity" min="0" value="' . (int) ($editingProduct['quantity'] ?? 0) . '" required></div></div><div class="inline"><button type="submit" name="save_product" class="btn">Save Product</button>';
    if ($editingProduct) {
        $content .= '<a href="index.php?page=products" class="btn secondary">Cancel</a>';
    }
    $content .= '</div></form>';
    $content .= '</div>';
    $content .= '<div class="card"><h3>Product List</h3><table><thead><tr><th>Name</th><th>SKU</th><th>Supplier</th><th>Qty</th><th>Low</th><th>Action</th></tr></thead><tbody>';

    if (empty($products)) {
        $content .= '<tr><td colspan="6" class="muted">No products found.</td></tr>';
    } else {
        foreach ($products as $product) {
            $content .= '<tr><td>' . e($product['name']) . '</td><td>' . e($product['sku']) . '</td><td>' . e($product['supplier_name']) . '</td><td>' . (int) $product['quantity'] . '</td><td>' . (int) $product['reorder_level'] . '</td><td><a class="btn secondary" href="index.php?page=products&edit_product=' . (int) $product['id'] . '">Edit</a> <form method="post" style="display:inline"><input type="hidden" name="product_id" value="' . (int) $product['id'] . '"><button type="submit" name="toggle_product" class="btn danger">Deactivate</button></form></td></tr>';
        }
    }
    $content .= '</tbody></table></div>';
} elseif ($page === 'suppliers') {
    $search = trim((string) ($_GET['q'] ?? ''));
    $query = 'SELECT * FROM SUPPLIERS WHERE is_active = 1';
    $params = [];
    if ($search !== '') {
        $query .= ' AND (name LIKE :search OR contact_person LIKE :search OR phone LIKE :search OR email LIKE :search)';
        $params['search'] = '%' . $search . '%';
    }
    $query .= ' ORDER BY name ASC';
    $stmt = $db->prepare($query);
    $stmt->execute($params);
    $suppliers = $stmt->fetchAll();

    $supplierId = isset($_GET['edit_supplier']) ? (int) $_GET['edit_supplier'] : 0;
    $editingSupplier = null;
    if ($supplierId > 0) {
        $stmt = $db->prepare('SELECT * FROM SUPPLIERS WHERE id = :id');
        $stmt->execute(['id' => $supplierId]);
        $editingSupplier = $stmt->fetch();
    }

    $content = '<div class="notice">Phase 1 (50% complete). Locked for next phase: supplier bulk actions and reporting.</div>';
    $content .= '<div class="card"><h2>Suppliers</h2>';
    if ($message) { $content .= '<div class="alert success">' . e($message) . '</div>'; }
    if ($error) { $content .= '<div class="alert error">' . e($error) . '</div>'; }
    $content .= '<div class="inline" style="margin-bottom: 16px;"><form method="get" style="display:flex; gap:10px; width:100%; align-items:end;"><input type="hidden" name="page" value="suppliers"><div class="field" style="flex:1; min-width:180px;"><label>Search</label><input type="text" name="q" value="' . e($search) . '" placeholder="Supplier name"></div><button class="btn secondary" type="submit">Search</button></form></div>';
    $content .= '<h3>' . ($editingSupplier ? 'Edit Supplier' : 'Add Supplier') . '</h3><form method="post"><input type="hidden" name="id" value="' . ($editingSupplier['id'] ?? '') . '"><div class="grid two-col"><div class="field"><label>Name</label><input type="text" name="name" value="' . e($editingSupplier['name'] ?? '') . '" required></div><div class="field"><label>Contact Person</label><input type="text" name="contact_person" value="' . e($editingSupplier['contact_person'] ?? '') . '"></div><div class="field"><label>Phone</label><input type="text" name="phone" value="' . e($editingSupplier['phone'] ?? '') . '"></div><div class="field"><label>Email</label><input type="email" name="email" value="' . e($editingSupplier['email'] ?? '') . '"></div></div><div class="inline"><button type="submit" name="save_supplier" class="btn">Save Supplier</button>';
    if ($editingSupplier) {
        $content .= '<a href="index.php?page=suppliers" class="btn secondary">Cancel</a>';
    }
    $content .= '</div></form></div>';
    $content .= '<div class="card"><h3>Supplier List</h3><table><thead><tr><th>Name</th><th>Contact</th><th>Phone</th><th>Email</th><th>Action</th></tr></thead><tbody>';

    if (empty($suppliers)) {
        $content .= '<tr><td colspan="5" class="muted">No suppliers found.</td></tr>';
    } else {
        foreach ($suppliers as $supplier) {
            $content .= '<tr><td>' . e($supplier['name']) . '</td><td>' . e($supplier['contact_person']) . '</td><td>' . e($supplier['phone']) . '</td><td>' . e($supplier['email']) . '</td><td><a class="btn secondary" href="index.php?page=suppliers&edit_supplier=' . (int) $supplier['id'] . '">Edit</a> <form method="post" style="display:inline"><input type="hidden" name="supplier_id" value="' . (int) $supplier['id'] . '"><button type="submit" name="toggle_supplier" class="btn danger">Deactivate</button></form></td></tr>';
        }
    }
    $content .= '</tbody></table></div>';
} elseif ($page === 'stock') {
    $stmt = $db->query('SELECT p.id, p.name, p.quantity, p.reorder_level FROM PRODUCTS p WHERE p.is_active = 1 ORDER BY p.name ASC');
    $products = $stmt->fetchAll();
    $history = getRecentTransactions($db, 12);

    $content = '<div class="notice">Phase 1 (50% complete). Locked for next phase: multi-item batch stock updates and exports.</div>';
    $content .= '<div class="card"><h2>Stock Movement</h2>';
    if ($message) { $content .= '<div class="alert success">' . e($message) . '</div>'; }
    if ($error) { $content .= '<div class="alert error">' . e($error) . '</div>'; }
    $content .= '<form method="post"><div class="grid two-col"><div class="field"><label>Product</label><select name="product_id" required><option value="">Select Product</option>';
    foreach ($products as $product) {
        $content .= '<option value="' . (int) $product['id'] . '">' . e($product['name']) . ' (' . (int) $product['quantity'] . ' on hand)</option>';
    }
    $content .= '</select></div><div class="field"><label>Movement</label><select name="type" required><option value="IN">Stock In</option><option value="OUT">Stock Out</option></select></div><div class="field"><label>Quantity</label><input type="number" min="1" name="quantity" required></div><div class="field"><label>Notes</label><input type="text" name="notes" placeholder="Optional note"></div></div><div class="inline"><button type="submit" name="post_stock" class="btn">Post Movement</button></div></form></div>';
    $content .= '<div class="card"><h3>Recent Transactions</h3><table><thead><tr><th>Product</th><th>Type</th><th>Qty</th><th>Before</th><th>After</th><th>User</th><th>Date</th></tr></thead><tbody>';
    if (empty($history)) {
        $content .= '<tr><td colspan="7" class="muted">No transactions yet.</td></tr>';
    } else {
        foreach ($history as $row) {
            $content .= '<tr><td>' . e($row['product_name']) . '</td><td>' . e($row['type']) . '</td><td>' . (int) $row['quantity'] . '</td><td>' . (int) $row['before_quantity'] . '</td><td>' . (int) $row['after_quantity'] . '</td><td>' . e($row['user_name']) . '</td><td>' . e($row['created_at']) . '</td></tr>';
        }
    }
    $content .= '</tbody></table></div>';
} else {
    $stats = getDashboardStats($db);
    $lowStock = getLowStockList($db);
    $latest = getRecentTransactions($db, 5);

    $content = '<div class="notice">Phase 1 (50% complete). Locked for next phase: admin user management, audit logs, and advanced reporting.</div>';
    $content .= '<div class="card"><h2>Dashboard</h2>';
    if ($message) { $content .= '<div class="alert success">' . e($message) . '</div>'; }
    if ($error) { $content .= '<div class="alert error">' . e($error) . '</div>'; }
    $content .= '<div class="grid two-col"><div class="stat"><h3>In Stock</h3><div class="value">' . $stats['in_stock'] . '</div></div><div class="stat"><h3>Low Stock</h3><div class="value">' . $stats['low_stock'] . '</div></div><div class="stat"><h3>Out of Stock</h3><div class="value">' . $stats['out_of_stock'] . '</div></div><div class="stat"><h3>Total Active Products</h3><div class="value">' . $stats['total'] . '</div></div></div></div>';

    $content .= '<div class="card"><h3>Low Stock List</h3><table><thead><tr><th>Product</th><th>Supplier</th><th>Qty</th><th>Reorder</th></tr></thead><tbody>';
    if (empty($lowStock)) {
        $content .= '<tr><td colspan="4" class="muted">No low-stock items.</td></tr>';
    } else {
        foreach ($lowStock as $row) {
            $content .= '<tr><td>' . e($row['name']) . '</td><td>' . e($row['supplier_name']) . '</td><td>' . (int) $row['quantity'] . '</td><td>' . (int) $row['reorder_level'] . '</td></tr>';
        }
    }
    $content .= '</tbody></table></div>';

    $content .= '<div class="card"><h3>Recent Transactions</h3><table><thead><tr><th>Product</th><th>Type</th><th>Qty</th><th>After</th><th>Date</th></tr></thead><tbody>';
    if (empty($latest)) {
        $content .= '<tr><td colspan="5" class="muted">No transactions yet.</td></tr>';
    } else {
        foreach ($latest as $row) {
            $content .= '<tr><td>' . e($row['product_name']) . '</td><td>' . e($row['type']) . '</td><td>' . (int) $row['quantity'] . '</td><td>' . (int) $row['after_quantity'] . '</td><td>' . e($row['created_at']) . '</td></tr>';
        }
    }
    $content .= '</tbody></table></div>';
}

$user = ['name' => $_SESSION['user_name'], 'role' => $_SESSION['user_role']];

if ($page === 'products' && $_SESSION['user_role'] !== 'Admin' && $_SESSION['user_role'] !== 'Manager') {
    http_response_code(403);
    echo renderLayout('Access denied', '<div class="card"><h2>Access denied</h2><p>You are not allowed to access product management.</p></div>', $page, $user);
    exit;
}

if ($page === 'suppliers' && $_SESSION['user_role'] !== 'Admin' && $_SESSION['user_role'] !== 'Manager') {
    http_response_code(403);
    echo renderLayout('Access denied', '<div class="card"><h2>Access denied</h2><p>You are not allowed to access supplier management.</p></div>', $page, $user);
    exit;
}

if ($page === 'stock' && $_SESSION['user_role'] !== 'Admin' && $_SESSION['user_role'] !== 'Manager' && $_SESSION['user_role'] !== 'Staff') {
    http_response_code(403);
    echo renderLayout('Access denied', '<div class="card"><h2>Access denied</h2><p>You are not allowed to post stock movements.</p></div>', $page, $user);
    exit;
}

echo renderLayout('Inventory System', $content, $page, $user);

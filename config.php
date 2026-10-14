<?php

define('DB_HOST', '127.0.0.1');
define('DB_NAME', 'cse1_inventory');
define('DB_USER', 'root');
define('DB_PASS', '');

$totpKeyFile = getenv('CSE1_TOTP_KEY_FILE');
if ($totpKeyFile === false || $totpKeyFile === '') {
    $totpKeyFile = dirname(dirname(__DIR__)) . DIRECTORY_SEPARATOR . 'apache' . DIRECTORY_SEPARATOR . 'conf' . DIRECTORY_SEPARATOR . 'cse1-totp.key';
}

if (!is_file($totpKeyFile)) {
    $keyHandle = @fopen($totpKeyFile, 'x');
    if ($keyHandle !== false) {
        $newKey = bin2hex(random_bytes(32)) . PHP_EOL;
        $written = fwrite($keyHandle, $newKey);
        $flushed = fflush($keyHandle);
        fclose($keyHandle);

        if ($written !== strlen($newKey) || !$flushed) {
            unlink($totpKeyFile);
            throw new RuntimeException('Could not create the 2FA encryption key. Check write permissions for ' . dirname($totpKeyFile) . '.');
        }
    } elseif (!is_file($totpKeyFile)) {
        throw new RuntimeException('Could not create the 2FA encryption key. Check write permissions for ' . dirname($totpKeyFile) . '.');
    }
}

$totpKey = is_readable($totpKeyFile) ? file_get_contents($totpKeyFile) : false;
define('TOTP_ENCRYPTION_KEY', $totpKey === false ? '' : trim($totpKey));

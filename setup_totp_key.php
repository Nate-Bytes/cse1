<?php

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

$keyFile = getenv('CSE1_TOTP_KEY_FILE');
if ($keyFile === false || $keyFile === '') {
    $keyFile = dirname(dirname(__DIR__)) . DIRECTORY_SEPARATOR . 'apache' . DIRECTORY_SEPARATOR . 'conf' . DIRECTORY_SEPARATOR . 'cse1-totp.key';
}

$keyDirectory = dirname($keyFile);
if (!is_dir($keyDirectory) || !is_writable($keyDirectory)) {
    fwrite(STDERR, "The 2FA key directory does not exist or is not writable: {$keyDirectory}" . PHP_EOL);
    exit(1);
}

$handle = @fopen($keyFile, 'x');
if ($handle === false) {
    if (is_file($keyFile)) {
        fwrite(STDOUT, "The 2FA encryption key already exists; it was not changed." . PHP_EOL);
        exit(0);
    }

    fwrite(STDERR, "Could not create the 2FA encryption key file: {$keyFile}" . PHP_EOL);
    exit(1);
}

$key = bin2hex(random_bytes(32)) . PHP_EOL;
$written = fwrite($handle, $key);
$flushed = fflush($handle);
fclose($handle);

if ($written !== strlen($key) || !$flushed) {
    unlink($keyFile);
    fwrite(STDERR, "Could not write the 2FA encryption key file completely." . PHP_EOL);
    exit(1);
}

fwrite(STDOUT, "Created the 2FA encryption key outside the web root. Keep this file private and backed up: {$keyFile}" . PHP_EOL);

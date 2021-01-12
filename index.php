<?php

declare(strict_types=1);

use Proton\X509Sign\Server;

if (file_exists(__DIR__ . '/vendor/autoload.php')) {
    require __DIR__ . '/vendor/autoload.php';
}

set_error_handler(function ($severity, $message, $file, $line) {
    throw new ErrorException($message, 0, $severity, $file, $line);
});

header('Content-type: application/json');

(new Server(
    getenv('SIGNATURE_PRIVATE_KEY') ?: null,
    getenv('SIGNATURE_PRIVATE_KEY_PASSPHRASE') ?: null,
    getenv('EXTENSIONS') ?: null,
))->handleRequests(
    json_decode(file_get_contents('php://input') ?: '{}', true) ?: [],
);

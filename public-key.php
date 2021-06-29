<?php

declare(strict_types=1);

use Proton\X509Sign\Server;

if (file_exists(__DIR__ . '/vendor/autoload.php')) {
    require __DIR__ . '/vendor/autoload.php';
}

set_error_handler(function ($severity, $message, $file, $line) {
    throw new ErrorException($message, 0, $severity, $file, $line);
});

ob_start();
Server::fromEnv()->handleRequests(['publicKey' => []]);
$json = ob_get_contents();
ob_end_clean();

echo json_decode($json, true)['publicKey']['result'];

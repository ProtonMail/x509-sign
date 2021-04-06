<?php

declare(strict_types=1);

use phpseclib3\Crypt\DSA;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\RSA;
use phpseclib3\File\X509;
use Proton\X509Sign\Key;

require __DIR__ . '/vendor/autoload.php';

do {
    $keyModes = array_keys(Key::PRIVATE_KEY_MODES);
    $keyMode = readline('Choose a key mode among [' . implode(', ', $keyModes) . ']: ');

    if (!$keyMode || in_array($keyMode, $keyModes)) {
        break;
    }

    echo "Unknown mode.\n";
} while (true);

$keyMode = $keyMode ?: Key::EC;

function createKey(string $mode)
{
    switch ($mode) {
        case Key::EC: return EC::createKey('Ed25519');
        case Key::RSA: return RSA::createKey();
        case Key::DSA: return DSA::createKey(2048, 224);
    }
}

$keyFile = readline('Enter a private key file to load or leave blank to generate a new one: ');
$keyPassword = null;

if ($keyFile) {
    $keyPassword = readline('Enter the key password if it has one: ') ?: '';

    if ($keyPassword === '') {
        $keyPassword = null;
    }
}

$extensions = readline('Enter the EXTENSIONS as a JSON value: ') ?: '';

$privateKey = $keyFile
    ? Key::loadPrivate($keyMode, file_get_contents($keyFile), $keyPassword)
    : createKey($keyMode);

$env = [
    'SIGNATURE_PRIVATE_KEY' => $privateKey->toString('PKCS8'),
    'SIGNATURE_PRIVATE_KEY_MODE' => $keyMode,
    'SIGNATURE_PRIVATE_KEY_PASSPHRASE' => $keyPassword,
    'EXTENSIONS' => $extensions === '' ? null : $extensions,
];

$dnProperties = [
    'countryName' => 'CH',
    'stateOrProvinceName' => 'GE',
    'localityName' => 'Geneva',
    'organizationName' => 'ProtonVPN',
    'organizationalUnitName' => 'ProtonVPN Certificate Authority',
    'commonName' => 'ProtonVPN',
    'emailAddress' => 'proton@protonvpn.com',
];

foreach ($dnProperties as $key => $value) {
    $input = readline("Set a value for $key (or leave blank to use '$value'): ");

    if ($input) {
        $dnProperties[$key] = $input;
    }
}

file_put_contents(__DIR__ . '/storage/env.php', '<?php return ' . var_export($env, true) . ';');

$publicKey = $privateKey->getPublicKey();

$CASubject = new X509;
$CASubject->setDN($dnProperties);
$CASubject->setPublicKey($publicKey);

$CAIssuer = new X509;
$CAIssuer->setPrivateKey($privateKey);
$CAIssuer->setDN($CASubject->getDN());

$x509 = new X509;
$x509->makeCA();
$result = $x509->sign($CAIssuer, $CASubject);

file_put_contents(__DIR__ . '/storage/ca.pem', (string) $x509->saveX509($result));

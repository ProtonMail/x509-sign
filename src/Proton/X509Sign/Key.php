<?php

declare(strict_types=1);

namespace Proton\X509Sign;

use phpseclib3\Crypt\Common\AsymmetricKey;
use phpseclib3\Crypt\Common\PrivateKey;
use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\Crypt\DSA;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\RSA;

final class Key
{
    public const RSA = 'RSA';
    public const DH = 'DH';
    public const DSA = 'DSA';
    public const EC = 'EC';

    public const PRIVATE_KEY_MODES = [
        self::RSA => RSA::class,
        // Not yet supported by phpseclib
        // self::DH => DH::class,
        self::DSA => DSA::class,
        self::EC => EC::class,
    ];

    public static function getMode(object $key): ?string
    {
        foreach (self::PRIVATE_KEY_MODES as $mode => $namespace) {
            if (is_a($key, "$namespace\PrivateKey")) {
                return $mode;
            }
        }

        return null;
    }

    public static function loadPrivate(string $mode, string $key, ?string $password = null): PrivateKey
    {
        /** @var PrivateKey $privateKey */
        $privateKey = self::load($mode, $key, $password);

        return $privateKey;
    }

    public static function loadPublic(string $mode, string $key, ?string $password = null): PublicKey
    {
        /** @var PublicKey $publicKey */
        $publicKey = self::load($mode, $key, $password);

        return $publicKey;
    }

    private static function load(string $mode, string $key, ?string $password = null): AsymmetricKey
    {
        return (self::PRIVATE_KEY_MODES[$mode])::load($key, $password ?? false);
    }
}

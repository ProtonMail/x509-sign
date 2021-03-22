<?php

declare(strict_types=1);

namespace Tests\Proton\X509Sign\Unit;

use phpseclib3\Crypt\DH;
use phpseclib3\Crypt\DSA;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\RSA;
use Proton\X509Sign\Key;
use stdClass;
use Tests\Proton\X509Sign\TestCase;
use Throwable;

/**
 * @coversDefaultClass \Proton\X509Sign\Key
 */
class KeyTest extends TestCase
{
    /**
     * @covers ::getMode
     */
    public function testGetMode(): void
    {
        self::assertSame(Key::EC, Key::getMode(EC::createKey('Ed25519')));
        self::assertSame(Key::RSA, Key::getMode(RSA::createKey()));
        self::assertSame(Key::DSA, Key::getMode(DSA::createKey(2048, 224)));
        // Not yet supported by phpseclib
        // self::assertSame(Key::DH, Key::getMode(DH::createKey(DH::createParameters(1024))));
        self::assertNull(Key::getMode(new stdClass()));
    }

    /**
     * @covers ::load
     * @covers ::loadPrivate
     */
    public function testLoadPrivate(): void
    {
        $privateKey = EC::createKey('Ed25519');
        $privateKeyString = $privateKey->toString('PKCS8');
        $publicKeyString = $privateKey->getPublicKey()->toString('PKCS8');

        self::assertSame($privateKeyString, Key::loadPrivate(Key::EC, $privateKeyString)->toString('PKCS8'));

        $message = null;

        try {
            Key::loadPrivate(Key::EC, $publicKeyString)->toString('PKCS8');
        } catch (Throwable $exception) {
            $message = $exception->getMessage();
        }

        self::assertStringContainsString('PrivateKey', $message);
    }

    /**
     * @covers ::load
     * @covers ::loadPublic
     */
    public function testLoadPublic(): void
    {
        $privateKey = EC::createKey('Ed25519');
        $privateKeyString = $privateKey->toString('PKCS8');
        $publicKeyString = $privateKey->getPublicKey()->toString('PKCS8');

        $message = null;

        try {
            Key::loadPublic(Key::EC, $privateKeyString)->toString('PKCS8');
        } catch (Throwable $exception) {
            $message = $exception->getMessage();
        }

        self::assertStringContainsString('PublicKey', $message);

        self::assertSame($publicKeyString, Key::loadPublic(Key::EC, $publicKeyString)->toString('PKCS8'));
    }
}

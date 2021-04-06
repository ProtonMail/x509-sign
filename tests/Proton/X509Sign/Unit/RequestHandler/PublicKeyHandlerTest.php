<?php

declare(strict_types=1);

namespace Tests\Proton\X509Sign\Unit\RequestHandler;

use phpseclib3\Crypt\RSA\PrivateKey;
use phpseclib3\Exception\NoKeyLoadedException;
use Proton\X509Sign\RequestHandler\PublicKeyHandler;
use Tests\Proton\X509Sign\TestCase;

/**
 * @covers \Proton\X509Sign\RequestHandler\PublicKeyHandler::handle
 */
class PublicKeyHandlerTest extends TestCase
{
    public function testHandle(): void
    {
        $handler = new PublicKeyHandler();
        /** @var PrivateKey $privateKey */
        $privateKey = PrivateKey::createKey()->withPassword('Le petit chien est sur la pente fatale.');

        $result = $handler->handle($privateKey);

        self::assertSame($privateKey->getPublicKey()->toString('PKCS8'), $result);

        $result = $handler->handle(
            $privateKey,
            [],
            ['format' => 'OpenSSH'],
        );

        self::assertSame($privateKey->getPublicKey()->toString('OpenSSH'), $result);
    }

    public function testHandleWrongKey(): void
    {
        $handler = new PublicKeyHandler();
        /** @var PrivateKey $privateKey */
        $privateKey = PrivateKey::createKey()->withPassword('Correct');

        $result = $handler->handle(
            PrivateKey::createKey()->withPassword('Correct'),
            [],
            ['format' => 'OpenSSH'],
        );

        self::assertNotSame($privateKey->getPublicKey()->toString('OpenSSH'), $result);
    }
}

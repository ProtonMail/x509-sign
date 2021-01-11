<?php

declare(strict_types=1);

namespace Tests\Proton\X509Sign\RequestHandler;

use phpseclib3\Crypt\RSA\PrivateKey;
use phpseclib3\Exception\NoKeyLoadedException;
use PHPUnit\Framework\TestCase;
use Proton\X509Sign\RequestHandler\PublicKeyHandler;

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

        $result = $handler->handle(
            $privateKey->toString('PKCS1'),
            'Le petit chien est sur la pente fatale.',
        );

        self::assertSame($privateKey->getPublicKey()->toString('PKCS1'), $result);

        $result = $handler->handle(
            $privateKey->toString('PKCS8'),
            'Le petit chien est sur la pente fatale.',
            ['format' => 'OpenSSH'],
        );

        self::assertSame($privateKey->getPublicKey()->toString('OpenSSH'), $result);
    }

    public function testHandleWrongPass(): void
    {
        self::expectException(NoKeyLoadedException::class);
        self::expectExceptionMessage('Unable to read key');

        $handler = new PublicKeyHandler();
        /** @var PrivateKey $privateKey */
        $privateKey = PrivateKey::createKey()->withPassword('Le petit chien est sur la pente fatale.');

        $handler->handle(
            $privateKey->toString('PKCS8'),
            "Le code, c'est `Le Code` ?",
            ['format' => 'OpenSSH'],
        );
    }

    public function testHandleWrongKey(): void
    {
        $handler = new PublicKeyHandler();
        /** @var PrivateKey $privateKey */
        $privateKey = PrivateKey::createKey()->withPassword('Correct');

        $result = $handler->handle(
            PrivateKey::createKey()->withPassword('Correct')->toString('PKCS8'),
            'Correct',
            ['format' => 'OpenSSH'],
        );

        self::assertNotSame($privateKey->getPublicKey()->toString('OpenSSH'), $result);
    }
}

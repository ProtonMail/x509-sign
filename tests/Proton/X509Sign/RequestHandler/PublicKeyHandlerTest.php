<?php

declare(strict_types=1);

namespace Tests\Proton\X509Sign\RequestHandler;

use phpseclib3\Crypt\RSA\PrivateKey;
use PHPUnit\Framework\TestCase;
use Proton\X509Sign\RequestHandler\PublicKeyHandler;

class PublicKeyHandlerTest extends TestCase
{
    public function testHandle(): void
    {
        $handler = new PublicKeyHandler();
        $privateKey = PrivateKey::createKey()->withPassword('Le petit chien est sur la pente fatale.');

        $result = iterator_to_array($handler->handle(
            $privateKey->toString('PKCS1'),
            'Le petit chien est sur la pente fatale.',
        ));

        self::assertSame([$privateKey->getPublicKey()->toString('PKCS1')], $result);

        $result = iterator_to_array($handler->handle(
            $privateKey->toString('PKCS8'),
            'Le petit chien est sur la pente fatale.',
            ['format' => 'OpenSSH'],
        ));

        self::assertSame([$privateKey->getPublicKey()->toString('OpenSSH')], $result);


        $result = iterator_to_array($handler->handle(
            $privateKey->toString('PKCS8'),
            "Le code, c'est `Le Code` ?",
            ['format' => 'OpenSSH'],
        ));

        self::assertSame([$privateKey->getPublicKey()->toString('OpenSSH')], $result);
    }
}

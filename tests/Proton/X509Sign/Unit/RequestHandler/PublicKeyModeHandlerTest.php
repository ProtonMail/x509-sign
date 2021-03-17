<?php

declare(strict_types=1);

namespace Tests\Proton\X509Sign\Unit\RequestHandler;

use phpseclib3\Crypt\Common\PrivateKey;
use phpseclib3\Crypt\DSA;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\RSA;
use Proton\X509Sign\Key;
use Proton\X509Sign\RequestHandler\PublicKeyModeHandler;
use Tests\Proton\X509Sign\TestCase;

/**
 * @covers \Proton\X509Sign\RequestHandler\PublicKeyModeHandler::handle
 */
class PublicKeyModeHandlerTest extends TestCase
{
    public function testHandle(): void
    {
        $handler = new PublicKeyModeHandler();

        self::assertSame(Key::RSA, $handler->handle(RSA::createKey()));
        self::assertSame(Key::EC, $handler->handle(EC::createKey('ed25519')));
        self::assertSame(Key::DSA, $handler->handle(DSA::createKey()));
        self::assertSame('unknown', $handler->handle(new class () implements PrivateKey {
            public function sign($message)
            {
                // noop
            }

            public function getPublicKey()
            {
                // noop
            }

            public function toString($type, array $options = [])
            {
                // noop
            }

            public function withPassword($string)
            {
                // noop
            }
        }));
    }
}

<?php

declare(strict_types=1);

namespace Tests\Proton\X509Sign\Unit\RequestHandler;

use phpseclib3\Crypt\RSA\PrivateKey;
use Proton\X509Sign\RequestHandler\CertificateAuthorityHandler;
use Tests\Proton\X509Sign\TestCase;

/**
 * @covers \Proton\X509Sign\RequestHandler\CertificateAuthorityHandler::handle
 */
class CertificateAuthorityHandlerTest extends TestCase
{
    public function testHandle(): void
    {
        $file = __DIR__ . '/../../../../../storage/ca.pem';
        $contents = @file_get_contents($file) ?: '';
        $text = 's' . mt_rand();
        file_put_contents($file, $text);
        $handler = new CertificateAuthorityHandler();
        /** @var PrivateKey $privateKey */
        $privateKey = PrivateKey::createKey();
        $result = $handler->handle($privateKey);
        file_put_contents($file, $contents);

        self::assertSame($text, $result);
    }
}

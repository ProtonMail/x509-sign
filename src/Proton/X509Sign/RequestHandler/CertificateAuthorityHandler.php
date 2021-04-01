<?php

declare(strict_types=1);

namespace Proton\X509Sign\RequestHandler;

use phpseclib3\Crypt\Common\PrivateKey;
use phpseclib3\File\X509;
use Proton\X509Sign\RequestHandlerInterface;

final class CertificateAuthorityHandler implements RequestHandlerInterface
{
    public function handle(
        PrivateKey $privateKey,
        ?string $extensionsJsonString = null,
        array $data = []
    ): string {
        return file_get_contents(__DIR__ . '/../../../../storage/ca.pem');
    }
}

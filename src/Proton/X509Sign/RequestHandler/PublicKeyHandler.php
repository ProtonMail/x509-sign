<?php

declare(strict_types=1);

namespace Proton\X509Sign\RequestHandler;

use phpseclib3\Crypt\Common\PrivateKey;
use Proton\X509Sign\RequestHandlerInterface;

final class PublicKeyHandler implements RequestHandlerInterface
{
    /**
     * @param PrivateKey $privateKey
     * @param string|null $extensionsJsonString
     * @param array{
     *     mode: Key::EC | Key::RSA | Key::DSA,
     *     format?: 'MSBLOB' | 'OpenSSH' | 'PKCS1' | 'PKCS8' | 'PSS' | 'PuTTY' | 'XML',
     * } $data
     * @return string
     */
    public function handle(
        PrivateKey $privateKey,
        ?string $extensionsJsonString = null,
        array $data = []
    ): string {
        return $privateKey->getPublicKey()->toString($data['format'] ?? 'PKCS8');
    }
}

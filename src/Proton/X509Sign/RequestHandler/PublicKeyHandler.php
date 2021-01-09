<?php

declare(strict_types=1);

namespace Proton\X509Sign\RequestHandler;

use phpseclib3\Crypt\RSA\PrivateKey;
use Proton\X509Sign\RequestHandlerInterface;

class PublicKeyHandler implements RequestHandlerInterface
{
    /**
     * @param string $privateKey
     * @param string|null $privateKeyPassPhrase
     * @param array{format?: 'MSBLOB' | 'OpenSSH' | 'PXCS1' | 'PXCS18' | 'PSS' | 'PuTTY' | 'XML'} $data
     *
     * @return string
     */
    public function handle(string $privateKey, ?string $privateKeyPassPhrase, array $data = [])
    {
        return PrivateKey::load($privateKey, $privateKeyPassPhrase ?? false)
                ->getPublicKey()
                ->toString($data['format'] ?? 'PKCS1');
    }
}

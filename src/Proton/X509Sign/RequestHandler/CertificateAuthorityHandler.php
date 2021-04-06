<?php

declare(strict_types=1);

namespace Proton\X509Sign\RequestHandler;

use phpseclib3\Crypt\Common\PrivateKey;
use phpseclib3\File\X509;
use Proton\X509Sign\RequestHandlerInterface;

final class CertificateAuthorityHandler implements RequestHandlerInterface
{
    /**
     * @param PrivateKey $privateKey
     * @param array{
     *  CA_FILE: string,
     *  SIGNATURE_PRIVATE_KEY: string,
     *  SIGNATURE_PRIVATE_KEY_MODE?: string|null,
     *  SIGNATURE_PRIVATE_KEY_PASSPHRASE?: string|null,: string,
     *  EXTENSIONS?: string|null,
     * } $config
     * @param array $data
     * @return string
     */
    public function handle(PrivateKey $privateKey, array $config = [], array $data = []): string
    {
        return file_get_contents($config['CA_FILE']);
    }
}

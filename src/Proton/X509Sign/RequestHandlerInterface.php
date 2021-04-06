<?php

declare(strict_types=1);

namespace Proton\X509Sign;

use phpseclib3\Crypt\Common\PrivateKey;

interface RequestHandlerInterface
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
    public function handle(PrivateKey $privateKey, array $config, array $data): string;
}

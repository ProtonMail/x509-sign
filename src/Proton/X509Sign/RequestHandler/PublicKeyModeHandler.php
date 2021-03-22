<?php

declare(strict_types=1);

namespace Proton\X509Sign\RequestHandler;

use phpseclib3\Crypt\Common\PrivateKey;
use Proton\X509Sign\Key;
use Proton\X509Sign\RequestHandlerInterface;

final class PublicKeyModeHandler implements RequestHandlerInterface
{
    /**
     * @param PrivateKey $privateKey
     * @param string|null $extensionsJsonString
     * @param array $data
     * @return string Key::EC | Key::RSA | Key::DSA | 'unknown'
     */
    public function handle(
        PrivateKey $privateKey,
        ?string $extensionsJsonString = null,
        array $data = []
    ): string {
        return Key::getMode($privateKey) ?? 'unknown';
    }
}

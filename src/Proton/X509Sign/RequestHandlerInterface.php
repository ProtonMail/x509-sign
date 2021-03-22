<?php

declare(strict_types=1);

namespace Proton\X509Sign;

use phpseclib3\Crypt\Common\PrivateKey;

interface RequestHandlerInterface
{
    public function handle(
        PrivateKey $privateKey,
        ?string $extensionsJsonString,
        array $data
    ): string;
}

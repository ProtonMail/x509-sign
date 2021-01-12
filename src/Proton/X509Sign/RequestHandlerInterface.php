<?php

declare(strict_types=1);

namespace Proton\X509Sign;

interface RequestHandlerInterface
{
    public function handle(
        string $privateKey,
        ?string $privateKeyPassPhrase,
        ?string $extensionsJsonString,
        array $data
    );
}

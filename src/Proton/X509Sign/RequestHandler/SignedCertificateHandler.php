<?php

declare(strict_types=1);

namespace Proton\X509Sign\RequestHandler;

use Proton\X509Sign\RequestHandlerInterface;

class SignedCertificateHandler implements RequestHandlerInterface
{
    public function handle(string $privateKey, ?string $privateKeyPassPhrase, array $data)
    {
        // TODO: Implement handle() method.
    }
}

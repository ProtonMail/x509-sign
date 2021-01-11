<?php

declare(strict_types=1);

namespace Tests\Proton\X509Sign\Fixture;

use phpseclib3\Crypt\RSA\PrivateKey;
use phpseclib3\Crypt\RSA\PublicKey;

final class User
{
    private PrivateKey $userKey;

    private array $subjectDn = [
        'commonName' => 'Bob'
    ];

    public function __construct()
    {
        /** @var PrivateKey $clientPrivateKey */
        $clientPrivateKey = PrivateKey::createKey();

        $this->userKey = $clientPrivateKey;
    }

    /**
     * @return string
     */
    public function getPublicKey(): string
    {
        /** @var PublicKey $publicKey */
        $publicKey = $this->userKey->getPublicKey();

        return $publicKey->toString('PKCS1');
    }

    /**
     * @return array|string[]
     */
    public function getSubjectDn(): array
    {
        return $this->subjectDn;
    }
}

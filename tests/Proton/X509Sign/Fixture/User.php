<?php

declare(strict_types=1);

namespace Tests\Proton\X509Sign\Fixture;

use phpseclib3\Crypt\RSA\PrivateKey;
use phpseclib3\Crypt\RSA\PublicKey;

final class User
{
    private array $subjectDn = [
        'commonName' => 'Alan'
    ];

    private PrivateKey $userKey;

    private string $certificate;

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

        return $publicKey->toString('PKCS8');
    }

    /**
     * @return array|string[]
     */
    public function getSubjectDn(): array
    {
        return $this->subjectDn;
    }

    public function use(Application $application): void
    {
        $application->receiveRequestFromUser($this);
    }

    public function receiveCertificate(string $certificate): void
    {
        $this->certificate = $certificate;
    }

    public function isSatisfiedWithItsCertificate(): bool
    {
        // TODO: make the user more exigent
        return is_string($this->certificate);
    }
}

<?php

declare(strict_types=1);

namespace Tests\Proton\X509Sign\Fixture;

use phpseclib3\Crypt\Common\PrivateKey;
use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\Crypt\EC;
use Proton\X509Sign\Key;

final class User
{
    private array $subjectDn = [
        'commonName' => 'Alan'
    ];

    private PrivateKey $userKey;

    private string $certificate;

    public function __construct(?PrivateKey $clientPrivateKey = null)
    {
        $this->userKey = $clientPrivateKey ?? EC::createKey('ed25519');
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
     * @return string|null
     */
    public function getPublicKeyMode(): ?string
    {
        return Key::getMode($this->userKey);
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

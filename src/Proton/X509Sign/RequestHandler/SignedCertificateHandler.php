<?php

declare(strict_types=1);

namespace Proton\X509Sign\RequestHandler;

use phpseclib3\Crypt\Common\PrivateKey;
use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\File\X509;
use Proton\X509Sign\Issuer;
use Proton\X509Sign\Key;
use Proton\X509Sign\RequestHandlerInterface;
use RuntimeException;

final class SignedCertificateHandler implements RequestHandlerInterface
{
    protected Issuer $issuer;

    public function __construct(?Issuer $issuer = null)
    {
        $this->issuer = $issuer ?? new Issuer();
    }

    /**
     * @param PrivateKey $privateKey
     * @param array{
     *  CA_FILE: string,
     *  SIGNATURE_PRIVATE_KEY: string,
     *  SIGNATURE_PRIVATE_KEY_MODE?: string|null,
     *  SIGNATURE_PRIVATE_KEY_PASSPHRASE?: string|null,: string,
     *  EXTENSIONS?: string|null,
     * } $config
     * @param array{
     *     mode: Key::EC | Key::RSA | Key::DSA,
     *     certificate: string, clientPublicKey: string,
     * } $data
     * @return string
     */
    public function handle(PrivateKey $privateKey, array $config = [], array $data = []): string
    {
        /**
         * @var string $certificate
         * @var string $clientPublicKeyString
         */
        [
            'certificate' => $certificate,
            'clientPublicKey' => $clientPublicKeyString,
        ] = $data;

        $clientPublicKey = Key::loadPublic($data['mode'] ?? Key::EC, $clientPublicKeyString);

        if (isset($config['EXTENSIONS'])) {
            $this->loadExtensions(json_decode($config['EXTENSIONS'], true));
        }

        $result = $this->reIssueCertificate($certificate, $privateKey, $clientPublicKey);

        if (!$result) {
            throw new RuntimeException('Unable to sign the CSR.');
        }

        return $result;
    }

    protected function reIssueCertificate(string $certificate, PrivateKey $issuerKey, PublicKey $subjectKey): ?string
    {
        $x509 = new X509();
        $data = $x509->loadX509($certificate);

        if (!isset($data['tbsCertificate'])) {
            return null;
        }

        $certificateData = $data['tbsCertificate'];

        return $this->issuer->issue(
            $issuerKey,
            $subjectKey,
            $x509->getIssuerDN(),
            $x509->getSubjectDN(),
            (string) $certificateData['serialNumber'],
            $certificateData['validity']['notBefore']['utcTime'],
            $certificateData['validity']['notAfter']['utcTime'],
            $this->getExtensionsValues($certificateData),
        );
    }

    protected function getExtensionsValues(array $certificateData): iterable
    {
        foreach (($certificateData['extensions'] ?? []) as $extension) {
            [
                'extnId' => $id,
                'extnValue' => $value,
            ] = $extension;

            yield $id => $value;
        }
    }

    protected function loadExtensions(array $extensions): void
    {
        $this->issuer->loadExtensions($extensions);
    }
}

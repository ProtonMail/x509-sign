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
     *     clientPublicKey: string,
     *     certificate?: string,
     *     extensions?: array<string, array>,
     *     certificateData?: {
     *         serialNumber: string,
     *         issuerDN: array,
     *         subjectDN: array,
     *         notBefore: string,
     *         notAfter: string,
     *         extensions: array,
     *     },
     * } $data
     * @return string
     */
    public function handle(PrivateKey $privateKey, array $config = [], array $data = []): string
    {
        $clientPublicKey = Key::loadPublic($data['mode'] ?? Key::EC, $data['clientPublicKey']);

        if (isset($config['EXTENSIONS'])) {
            $this->loadExtensions(json_decode($config['EXTENSIONS'], true));
        }

        if (isset($data['extensions'])) {
            $this->loadExtensions($data['extensions']);
        }

        $result = isset($data['certificate'])
            ? $this->reIssueCertificate($data['certificate'], $privateKey, $clientPublicKey)
            : $this->issueCertificateData($data['certificateData'], $privateKey, $clientPublicKey);

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

    /**
     * @param array{
     *     serialNumber: string,
     *     issuerDN: array,
     *     subjectDN: array,
     *     notBefore: string,
     *     notAfter: string,
     *     extensions: array,
     * } $certificateData
     * @param PrivateKey $issuerKey
     * @param PublicKey $subjectKey
     * @return string|null
     */
    protected function issueCertificateData(array $certificateData, PrivateKey $issuerKey, PublicKey $subjectKey): ?string
    {
        return $this->issuer->issue(
            $issuerKey,
            $subjectKey,
            $certificateData['issuerDN'],
            $certificateData['subjectDN'],
            $certificateData['serialNumber'],
            $certificateData['notBefore'],
            $certificateData['notAfter'],
            $certificateData['extensions'],
            static function (X509 $authority, X509 $subject) {
                $subject->setKeyIdentifier(
                    $subject->computeKeyIdentifier($subject->getPublicKey()->toString('PKCS8')),
                );
            },
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

<?php

declare(strict_types=1);

namespace Proton\X509Sign\RequestHandler;

use phpseclib3\Crypt\RSA\PrivateKey;
use phpseclib3\Crypt\RSA\PublicKey;
use phpseclib3\File\X509;
use Proton\X509Sign\RequestHandlerInterface;
use RuntimeException;

class SignedCertificateHandler implements RequestHandlerInterface
{
    /**
     * @param string $privateKey
     * @param string|null $privateKeyPassPhrase
     * @param array{certificate: string, clientPublicKey: string} $data
     *
     * @return string
     */
    public function handle(string $privateKey, ?string $privateKeyPassPhrase, array $data): string
    {
        /** @var PrivateKey $privateKey */
        $privateKey = PrivateKey::load($privateKey, $privateKeyPassPhrase ?? false);

        /**
         * @var string $certificate
         * @var string $clientPublicKey
         */
        [
            'certificate' => $certificate,
            'clientPublicKey' => $clientPublicKeyString,
        ] = $data;

        /** @var PublicKey $clientPublicKey */
        $clientPublicKey = PublicKey::load($clientPublicKeyString);

        $x509 = new X509();
        $x509->makeCA();
        $data = $x509->loadX509($certificate);
        $certificateData = $data['tbsCertificate'];

        $subject = new X509();
        $subject->setPublicKey($clientPublicKey);
        $subject->setDN($x509->getSubjectDN());

        $issuer = new X509();
        $issuer->setPrivateKey($privateKey);
        $issuer->setDN($x509->getIssuerDN());

        $authority = new X509();
        $authority->makeCA();
        $authority->setSerialNumber((string) $certificateData['serialNumber'], 10);
        $authority->setStartDate($certificateData['validity']['notBefore']['utcTime']);
        $authority->setEndDate($certificateData['validity']['notAfter']['utcTime']);

        foreach ($certificateData['extensions'] as $extension) {
            [
                'extnId' => $id,
                'extnValue' => $value,
                'critical' => $critical,
            ] = $extension;
            $authority->setExtension($id, $value, $critical);
        }


        $result = $authority->saveX509($authority->sign($issuer, $subject));

        if (!$result) {
            throw new RuntimeException('Unable to sign the CSR.');
        }

        return $result;
    }
}

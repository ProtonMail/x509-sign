<?php

declare(strict_types=1);

namespace Tests\Proton\X509Sign;

use phpseclib3\File\X509;
use PHPUnit\Framework\TestCase as TestCaseBase;

class TestCase extends TestCaseBase
{
    /**
     * @param string $certificate
     * @return array{
     *     hours: int,
     *     issuer: array,
     *     subject: array,
     *     serialNumber: string,
     *     extensions: array,
     * }
     */
    protected function getCertificateData(string $certificate): array
    {
        $x509 = new X509();
        $data = $x509->loadX509($certificate);
        $time = strtotime($data['tbsCertificate']['validity']['notAfter']['utcTime']);
        $hours = (int) round(($time - time()) / 3600);
        $extensions = [];

        foreach ($data['tbsCertificate']['extensions'] as $extension) {
            $extensions[$extension['extnId']] = $extension['extnValue'] ?? null;
        }

        return [
            'hours' => $hours,
            'issuer' => $this->getRdnSequenceData($data['tbsCertificate']['issuer']),
            'subject' => $this->getRdnSequenceData($data['tbsCertificate']['subject']),
            'serialNumber' => (string) $data['tbsCertificate']['serialNumber'],
            'extensions' => $extensions,
        ];
    }

    private function getRdnSequenceData(array $sequence): array
    {
        $dnCopy = [];

        foreach (($sequence['rdnSequence'] ?? $sequence) as $item) {
            /**
             * @var string $type
             * @var string $value
             */
            ['type' => $type, 'value' => ['utf8String' => $value]] = $item[0];

            // Ignore namespace prefix
            $type = preg_replace('/^.*-at-/U', '', $type);

            $dnCopy[$type] = $value;
        }

        return $dnCopy;
    }
}

<?php

declare(strict_types=1);

namespace Proton\X509Sign;

use phpseclib3\Crypt\RSA\PrivateKey;
use phpseclib3\Crypt\RSA\PublicKey;
use phpseclib3\File\ASN1;
use phpseclib3\File\X509;

class Issuer
{
    protected array $extensions = [];

    public function issue(
        PrivateKey $issuerKey,
        PublicKey $subjectKey,
        array $issuerDn,
        array $subjectDn,
        ?string $serialNumber = null,
        $startDate = null,
        $endDate = null,
        iterable $extensions = []
    ): ?string {
        $subject = new X509();
        $subject->setPublicKey($subjectKey);
        $subject->setDN($subjectDn);

        $issuer = new X509();
        $issuer->setPrivateKey($issuerKey);
        $issuer->setDN($issuerDn);

        $authority = new X509();
        $authority->makeCA();

        if ($serialNumber) {
            $authority->setSerialNumber($serialNumber, 10);
        }

        if ($startDate) {
            $authority->setStartDate($startDate);
        }

        if ($endDate) {
            $authority->setEndDate($endDate);
        }

        foreach ($extensions as $id => $value) {
            if (isset($this->extensions[$id])) {
                $authority->setExtensionValue($id, $value);
            }
        }

        return $authority->saveX509($authority->sign($issuer, $subject)) ?: null;
    }

    public function loadExtensions(array $extensions): void
    {
        $ids = [];

        foreach ($extensions as [$name, $id, $structure]) {
            $this->extensions[$name] = $id;
            $ids[$name] = $id;

            X509::registerExtension($name, $structure);
        }

        ASN1::loadOIDs($ids);
    }
}

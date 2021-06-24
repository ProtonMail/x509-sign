<?php

declare(strict_types=1);

namespace Proton\X509Sign;

use DateTimeInterface;
use InvalidArgumentException;
use phpseclib3\Crypt\Common\PrivateKey;
use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\File\ASN1;
use phpseclib3\File\X509;

class Issuer
{
    protected array $extensions = [];

    /**
     * Issue a certificate.
     *
     * @param PrivateKey $issuerKey
     * @param PublicKey $subjectKey
     * @param array $issuerDn
     * @param array $subjectDn
     * @param string|null $serialNumber
     * @param DateTimeInterface|string|null $startDate
     * @param DateTimeInterface|string|null $endDate
     * @param iterable|array $extensions
     * @param callable|null $configX509
     * @return string|null
     */
    public function issue(
        PrivateKey $issuerKey,
        PublicKey $subjectKey,
        array $issuerDn,
        array $subjectDn,
        ?string $serialNumber = null,
        $startDate = null,
        $endDate = null,
        iterable $extensions = [],
        ?callable $configX509 = null
    ): ?string {
        $subject = new X509();
        $subject->setPublicKey($subjectKey);
        $subject->setDN($subjectDn);

        $issuer = new X509();
        $issuer->setPrivateKey($issuerKey);
        $issuer->setDN($issuerDn);

        $authority = new X509();

        if ($configX509) {
            $configX509($authority, $subject, $issuer);
        }

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
            if (isset($this->extensions[$id]) || preg_match('/^\d+(?:\.\d+)+$/', ASN1::getOID($id))) {
                $arguments = isset($value['value'], $value['critical'], $value['replace'])
                    ? [$value['value'], $value['critical'], $value['replace']]
                    : [$value];

                $authority->setExtensionValue($id, ...$arguments);
            }
        }

        return $authority->saveX509($authority->sign($issuer, $subject)) ?: null;
    }

    /**
     * Load extensions.
     *
     * Each extension must be an array with in order: id/name, oID, and structure.
     *
     * @param iterable<array{string, string, array}> $extensions List of array-definitions.
     */
    public function loadExtensions(iterable $extensions): void
    {
        $oids = [];

        foreach ($extensions as [$id, $oID, $structure]) {
            if (!is_string($id) || !is_string($oID)) {
                throw new InvalidArgumentException('Extension ID and OID must be strings');
            }

            $this->extensions[$id] = $oID;
            $oids[$id] = $oID;

            X509::registerExtension($id, $structure);
        }

        ASN1::loadOIDs($oids);
    }
}

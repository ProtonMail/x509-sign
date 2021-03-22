<?php

declare(strict_types=1);

namespace Proton\X509Sign;

use DateTimeInterface;
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
     * @param array{
     *     countryName?: string,
     *     organizationName?: string,
     *     dnQualifier?: string,?: string,
     *     commonName?: string,
     *     state?: string,
     *     province?: string,
     *     provincename?: string,
     *     localityName?: string,
     *     emailAddress?: string,
     *     serialNumber?: string,
     *     postalCode?: string,
     *     streetAddress?: string,
     *     name?: string,
     *     givenName?: string,
     *     surname?: string,
     *     initials?: string,
     *     generationQualifier?: string,
     *     organizationalUnitName?: string,
     *     pseudonym?: string,
     *     title?: string,
     *     description?: string,
     *     role?: string,
     *     uniqueidentifier?: string,
     * } $issuerDn
     * @param array{
     *     countryName?: string,
     *     organizationName?: string,
     *     dnQualifier?: string,?: string,
     *     commonName?: string,
     *     state?: string,
     *     province?: string,
     *     provincename?: string,
     *     localityName?: string,
     *     emailAddress?: string,
     *     serialNumber?: string,
     *     postalCode?: string,
     *     streetAddress?: string,
     *     name?: string,
     *     givenName?: string,
     *     surname?: string,
     *     initials?: string,
     *     generationQualifier?: string,
     *     organizationalUnitName?: string,
     *     pseudonym?: string,
     *     title?: string,
     *     description?: string,
     *     role?: string,
     *     uniqueidentifier?: string,
     * } $subjectDn
     * @param string|null $serialNumber
     * @param DateTimeInterface|string|null $startDate
     * @param DateTimeInterface|string|null $endDate
     * @param iterable|array $extensions
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
            $this->extensions[$id] = $oID;
            $oids[$id] = $oID;

            X509::registerExtension($id, $structure);
        }

        ASN1::loadOIDs($oids);
    }
}

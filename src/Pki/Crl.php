<?php

namespace MadWizard\WebAuthn\Pki;

use DateTimeImmutable;
use DateTimeZone;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Exception\VerificationException;
use phpseclib3\File\X509;

/**
 * @experimental
 */
final class Crl
{
    /**
     * @var X509
     */
    private $crl;

    /**
     * @var DateTimeImmutable|null
     */
    private $nextUpdate;

    /**
     * @param string $crlData CRL data as PEM or DER
     *
     * @throws ParseException        When CRL or issuer certificate could not be parsed.
     * @throws VerificationException When CRL signature is invalid
     */
    public function __construct(string $crlData, X509Certificate ...$caCertificates)
    {
        $crl = new X509();
        foreach ($caCertificates as $ca) {
            if ($crl->loadCA($ca->asDer()) === false) {
                throw new ParseException('Failed to load CA certificate for CRL.');
            }
        }

        $crlInfo = $crl->loadCRL($crlData);
        if ($crlInfo === false) {
            throw new ParseException('Failed to load CRL data.');
        }

        $nextUpdate = $crlInfo['tbsCertList']['nextUpdate']['utcTime'] ?? null;
        if ($nextUpdate !== null) {
            $this->nextUpdate = new DateTimeImmutable($nextUpdate, new DateTimeZone('UTC'));
        }

        if (true !== $crl->validateSignature()) {
            throw new VerificationException('Failed to verify CRL signature.');
        }
        $this->crl = $crl;
    }

    public function isRevoked(string $serial): bool
    {
        return $this->crl->getRevoked($serial) !== false;
    }

    public function getNextUpdate(): ?DateTimeImmutable
    {
        return $this->nextUpdate;
    }
}

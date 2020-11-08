<?php

namespace MadWizard\WebAuthn\Attestation\TrustPath;

use InvalidArgumentException;
use MadWizard\WebAuthn\Pki\X509Certificate;

final class CertificateTrustPath implements TrustPathInterface
{
    /**
     * @var X509Certificate[]
     */
    private $certificates;

    public function __construct(X509Certificate ...$certificates)
    {
        foreach ($certificates as $c) {
            if (!($c instanceof X509Certificate)) {
                throw new InvalidArgumentException(sprintf('Expecting array of X509Certificate objects.'));
            }
        }
        $this->certificates = $certificates;
    }

    public static function fromPemList(array $x5c): self
    {
        return new CertificateTrustPath(...array_map(static function (string $s): X509Certificate {
            return X509Certificate::fromPem($s);
        }, $x5c));
    }

    public static function fromBase64List(array $x5c): self
    {
        return new CertificateTrustPath(...array_map(static function (string $s): X509Certificate {
            return X509Certificate::fromBase64($s);
        }, $x5c));
    }

    /**
     * @return X509Certificate[]
     */
    public function getCertificates(): array
    {
        return $this->certificates;
    }

    /**
     * Returns certificates as a list of PEM encoded strings (including armor).
     *
     * @return string[]
     */
    public function asPemList(): array
    {
        return array_map(static function (X509Certificate $cert): string {
            return $cert->asPem();
        }, $this->certificates);
    }
}

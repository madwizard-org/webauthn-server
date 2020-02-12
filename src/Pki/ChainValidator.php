<?php


namespace MadWizard\WebAuthn\Pki;

use DateTimeImmutable;
use MadWizard\WebAuthn\Remote\Downloader;
use X509\Certificate\Certificate;
use X509\CertificationPath\CertificationPath;
use X509\CertificationPath\PathValidation\PathValidationConfig;

final class ChainValidator implements ChainValidatorInterface
{
    public const MAX_VALIDATION_LENGTH = 5;

    /**
     * @var Downloader|null
     */
    private $downloader;

    public function __construct(Downloader $downloader = null)
    {
        $this->downloader = $downloader;
    }

    private function getReferenceDate() : DateTimeImmutable
    {
        return new DateTimeImmutable();
    }

    public function validateChain(X509Certificate... $certificates) : bool
    {
        $pathCerts = array_map(function (X509Certificate $c) {
            return Certificate::fromDER($c->asDer());
        }, $certificates);
        $path = new CertificationPath(...$pathCerts);
        $config = new PathValidationConfig($this->getReferenceDate(), self::MAX_VALIDATION_LENGTH);
        try {
            $path->validate($config);
            return true;
        } catch (\Exception $e) {
            return false;
        }
    }
}

<?php


namespace MadWizard\WebAuthn\Pki;

use DateTimeImmutable;

use Exception;
use MadWizard\WebAuthn\Exception\VerificationException;
use Sop\X509\Certificate\Certificate;
use Sop\X509\CertificationPath\CertificationPath;
use Sop\X509\CertificationPath\PathValidation\PathValidationConfig;

final class ChainValidator implements ChainValidatorInterface
{
    public const MAX_VALIDATION_LENGTH = 5;

    /**
     * @var CertificateStatusResolverInterface|null
     */
    private $statusResolver;

    public function __construct(?CertificateStatusResolverInterface $statusResolver)
    {
        $this->statusResolver = $statusResolver;
    }

    private function getReferenceDate() : DateTimeImmutable
    {
        return new DateTimeImmutable();
    }

    private function validateCertificates(X509Certificate... $certificates)
    {
        try {
            $pathCerts = array_map(function (X509Certificate $c) {
                return Certificate::fromDER($c->asDer());
            }, $certificates);
            $path = new CertificationPath(...$pathCerts);
            $config = new PathValidationConfig($this->getReferenceDate(), self::MAX_VALIDATION_LENGTH);
        } catch (Exception $e) {
            throw new VerificationException('Failed to validate certificate: ' . $e->getMessage(), 0, $e);
        }
        try {
            $path->validate($config);
            return true;
        } catch (\Exception $e) {
            return false;
        }
    }

    public function validateChain(X509Certificate... $certificates) : bool
    {
        if ($this->validateCertificates(...$certificates)) {
            if ($this->statusResolver) {
                $numCerts = count($certificates);
                for ($i = 1; $i < $numCerts; $i++) {
                    if ($this->statusResolver->isRevoked($certificates[$i], $certificates[$i - 1])) {
                        return false;
                    }
                }
            }
            return true;
        }
        return false;
    }
}

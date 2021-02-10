<?php

namespace MadWizard\WebAuthn\Pki;

use DateTimeImmutable;
use Exception;
use MadWizard\WebAuthn\Exception\VerificationException;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;
use Psr\Log\NullLogger;
use Sop\X509\Certificate\Certificate;
use Sop\X509\CertificationPath\CertificationPath;
use Sop\X509\CertificationPath\Exception\PathValidationException;
use Sop\X509\CertificationPath\PathValidation\PathValidationConfig;

final class ChainValidator implements ChainValidatorInterface, LoggerAwareInterface
{
    use LoggerAwareTrait;

    public const MAX_VALIDATION_LENGTH = 5;

    /**
     * @var CertificateStatusResolverInterface
     */
    private $statusResolver;

    public function __construct(CertificateStatusResolverInterface $statusResolver)
    {
        $this->statusResolver = $statusResolver;
        $this->logger = new NullLogger();
    }

    private function getReferenceDate(): DateTimeImmutable
    {
        return new DateTimeImmutable();
    }

    private function validateCertificates(X509Certificate ...$certificates): bool
    {
        try {
            $pathCerts = array_map(function (X509Certificate $c) {
                return Certificate::fromDER($c->asDer());
            }, $certificates);
            $path = new CertificationPath(...$pathCerts);
            $config = new PathValidationConfig($this->getReferenceDate(), self::MAX_VALIDATION_LENGTH);
        } catch (Exception $e) {
            throw new VerificationException(sprintf('Failed to validate certificate: %s', $e->getMessage()), 0, $e);
        }
        try {
            $path->validate($config);
            return true;
        } catch (PathValidationException $e) {
            $this->logger->debug(sprintf('Path validation of certificate failed: %s', $e->getMessage()));
            return false;
        } catch (Exception $e) {
            throw new VerificationException(sprintf('Failed to validate certificate: %s', $e->getMessage()), 0, $e);
        }
    }

    public function validateChain(X509Certificate ...$certificates): bool
    {
        if ($this->validateCertificates(...$certificates)) {
            $numCerts = count($certificates);
            for ($i = 1; $i < $numCerts; $i++) {
                if ($this->statusResolver->isRevoked($certificates[$i], ...array_slice($certificates, 0, $i))) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }
}

<?php

namespace MadWizard\WebAuthn\Metadata;

use MadWizard\WebAuthn\Attestation\Identifier\AttestationKeyIdentifier;
use MadWizard\WebAuthn\Attestation\Identifier\IdentifierInterface;
use MadWizard\WebAuthn\Attestation\TrustAnchor\MetadataInterface;
use MadWizard\WebAuthn\Attestation\TrustPath\CertificateTrustPath;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Metadata\Provider\MetadataProviderInterface;
use MadWizard\WebAuthn\Pki\CertificateParser;
use MadWizard\WebAuthn\Server\Registration\RegistrationResultInterface;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;
use Psr\Log\NullLogger;

final class MetadataResolver implements MetadataResolverInterface, LoggerAwareInterface
{
    use LoggerAwareTrait;

    /**
     * @var MetadataProviderInterface[]
     */
    private $providers;

    public function __construct(array $providers)
    {
        $this->providers = $providers;
        $this->logger = new NullLogger();
    }

    private function determineIdentifier(RegistrationResultInterface $registrationResult): ?IdentifierInterface
    {
        // If a valid AAGUID is present, this is the main identifier. Do not look for others.
        $identifier = $registrationResult->getAuthenticatorData()->getAaguid();
        if ($identifier !== null && !$identifier->isZeroAaguid()) {
            return $identifier;
        }

        // If certificates are available, get the attestation certificate's public key identifier
        $trustPath = $registrationResult->getVerificationResult()->getTrustPath();
        if ($trustPath instanceof CertificateTrustPath) {
            $certs = $trustPath->getCertificates();
            if (isset($certs[0])) {
                return self::pkIdFromPemCertificate($certs[0]->asPem());
            }
        }
        return null;
    }

    public function getMetadata(RegistrationResultInterface $registrationResult): ?MetadataInterface
    {
        $identifier = $this->determineIdentifier($registrationResult);
        if ($identifier === null) {
            return null;
        }

        foreach ($this->providers as $provider) {
            try {
                $metadata = $provider->getMetadata($identifier, $registrationResult);
                if ($metadata !== null) {
                    return $metadata;
                }
            } catch (WebAuthnException $e) {
                $this->logger->warning(sprintf('Error retrieving metadata (%s) - ignoring provider', $e->getMessage()), ['exception' => $e]);
                continue;
            }
        }
        return null;
    }

    private static function pkIdFromPemCertificate(string $pem): IdentifierInterface
    {
        $parser = new CertificateParser();
        $cert = $parser->parsePem($pem);
        return new AttestationKeyIdentifier($cert->getPublicKeyIdentifier());
    }
}

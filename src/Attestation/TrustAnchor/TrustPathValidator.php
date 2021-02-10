<?php

namespace MadWizard\WebAuthn\Attestation\TrustAnchor;

use MadWizard\WebAuthn\Attestation\TrustPath\CertificateTrustPath;
use MadWizard\WebAuthn\Attestation\TrustPath\TrustPathInterface;
use MadWizard\WebAuthn\Pki\ChainValidatorInterface;
use MadWizard\WebAuthn\Pki\X509Certificate;
use function array_reverse;

final class TrustPathValidator implements TrustPathValidatorInterface
{
    /**
     * @var ChainValidatorInterface
     */
    private $chainValidator;

    public function __construct(ChainValidatorInterface $chainValidator)
    {
        $this->chainValidator = $chainValidator;
    }

    public function validate(TrustPathInterface $trustPath, TrustAnchorInterface $trustAnchor): bool
    {
        if ($trustAnchor instanceof CertificateTrustAnchor && $trustPath instanceof CertificateTrustPath) {
            // WebAauthn SPEC (v2):
            // Use  the X.509 certificates returned as the attestation trust path from the verification procedure
            // to verify that the attestation public key either correctly chains up to an acceptable root certificate,
            // or is itself an acceptable certificate
            // (i.e., it and the root certificate obtained in Step 20 may be the same).

            $trustAnchorCert = $trustAnchor->getCertificate();
            $trustPathCerts = $trustPath->getCertificates();

            // Check if trust path is trust anchor itself
            if (count($trustPathCerts) === 1 && $trustPathCerts[0]->equals($trustAnchorCert)) {
                return true;
            }

            $chain = array_merge([$trustAnchorCert], array_reverse($trustPath->getCertificates()));

            // RFC5280 6.1: "A certificate MUST NOT appear more than once in a prospective certification path."
            // https://github.com/fido-alliance/conformance-test-tools-resources/issues/605
            if ($this->containsDuplicates(...$chain)) {
                return false;
            }

            if ($this->chainValidator->validateChain(...$chain)) {
                return true;
            }
        }
        return false;
    }

    private function containsDuplicates(X509Certificate ...$chain): bool
    {
        $map = [];
        foreach ($chain as $cert) {
            $pem = $cert->asPem();
            if (isset($map[$pem])) {
                return true;
            }
            $map[$pem] = true;
        }
        return false;
    }
}

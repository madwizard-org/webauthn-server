<?php


namespace MadWizard\WebAuthn\Attestation\TrustAnchor;

use MadWizard\WebAuthn\Attestation\AttestationType;
use MadWizard\WebAuthn\Attestation\TrustPath\CertificateTrustPath;
use MadWizard\WebAuthn\Attestation\Verifier\VerificationResult;
use MadWizard\WebAuthn\Exception\WebAuthnException;

class U2FMetadataAnchor implements TrustAnchorInterface
{
    /**
     * @var string
     */
    private $filename;

    /**
     * @var array
     */
    private $json;

    public function __construct(string $metadataFile)
    {
        $this->filename = $metadataFile;
    }

    public function isTrusted(VerificationResult $verificationResult): TrustStatus
    {
        $trustPath = $verificationResult->getTrustPath();

        if ($verificationResult->getAttestationType() !== AttestationType::SELF || !($trustPath instanceof CertificateTrustPath)) {
            return TrustStatus::notTrusted();
        }

        $json = $this->getMetadataJson();


        if (!($trustPath instanceof CertificateTrustPath)) {
            throw new WebAuthnException('Expecting CertificateTrustPath');
        }

        $trusted = $json['trustedCertificates'];

        foreach ($trusted as $rootCert) {
            $trustPath->getCertificates();
        }
    }

    private function getMetadataJson()
    {
        if ($this->json !== null) {
            return $this->json;
        }

        $text = \file_get_contents($this->filename);
        if ($text === false) {
            throw new WebAuthnException(sprintf('Failed to read U2F metadata from file %s.', $this->filename));
        }

        $json = \json_decode($text, true);
        if ($json === false) {
            throw new WebAuthnException(sprintf('Failed to parse U2F metadata from file %s. Json error: %s.', $this->filename, \json_last_error_msg()));
        }
        $this->json = $json;

        // TODO validate
        return $json;
    }
}

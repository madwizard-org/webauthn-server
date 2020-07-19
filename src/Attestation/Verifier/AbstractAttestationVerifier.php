<?php

namespace MadWizard\WebAuthn\Attestation\Verifier;

use MadWizard\WebAuthn\Attestation\Identifier\Aaguid;
use MadWizard\WebAuthn\Exception\VerificationException;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Pki\CertificateDetailsInterface;

abstract class AbstractAttestationVerifier implements AttestationVerifierInterface
{
    protected function checkAaguidExtension(CertificateDetailsInterface $cert, Aaguid $validAaguid): void
    {
        try {
            $aaguid = $cert->getFidoAaguidExtensionValue();
        } catch (WebAuthnException $e) {
            throw new VerificationException('Failed to read fido aaguid extension.', 0, $e);
        }

        if ($aaguid === null) {
            return;
        }

        if (!$validAaguid->equals($aaguid)) {
            throw new VerificationException('AAGUID in certificate extension does not match the AAGUID in the authenticator data.');
        }
    }
}

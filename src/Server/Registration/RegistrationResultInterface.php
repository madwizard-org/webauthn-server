<?php

namespace MadWizard\WebAuthn\Server\Registration;

use MadWizard\WebAuthn\Attestation\AuthenticatorDataInterface;
use MadWizard\WebAuthn\Attestation\TrustAnchor\MetadataInterface;
use MadWizard\WebAuthn\Attestation\Verifier\VerificationResult;
use MadWizard\WebAuthn\Credential\CredentialId;
use MadWizard\WebAuthn\Crypto\CoseKeyInterface;

interface RegistrationResultInterface
{
    public function getCredentialId(): CredentialId;

    public function getPublicKey(): CoseKeyInterface;

    public function getVerificationResult(): VerificationResult;

    public function getSignatureCounter(): int;

    public function getAuthenticatorData(): AuthenticatorDataInterface;

    public function getMetadata(): ?MetadataInterface;
}

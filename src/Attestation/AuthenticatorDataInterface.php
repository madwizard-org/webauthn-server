<?php

namespace MadWizard\WebAuthn\Attestation;

use MadWizard\WebAuthn\Attestation\Identifier\Aaguid;
use MadWizard\WebAuthn\Crypto\CoseKeyInterface;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Format\ByteBuffer;

interface AuthenticatorDataInterface
{
    public function getRpIdHash(): ByteBuffer;

    public function getSignCount(): int;

    public function isUserPresent(): bool;

    public function isUserVerified(): bool;

    public function hasAttestedCredentialData(): bool;

    public function hasExtensionData(): bool;

    public function getCredentialId(): ?ByteBuffer;

    /**
     * @return CoseKeyInterface
     * @throws WebAuthnException when authenticator data does not contain a key.
     * @see hasKey
     */
    public function getKey(): CoseKeyInterface;

    public function hasKey(): bool;

    public function hasAaguid(): bool;

    public function getAaguid(): Aaguid;

    /**
     * @return ByteBuffer
     */
    public function getRaw(): ByteBuffer;
}

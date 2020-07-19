<?php

namespace MadWizard\WebAuthn\Attestation;

use MadWizard\WebAuthn\Format\ByteBuffer;

interface AttestationObjectInterface
{
    public function getFormat(): string;

    public function getStatement(): array;

    public function getAuthenticatorData(): ByteBuffer;
}

<?php

namespace MadWizard\WebAuthn\Dom;

use MadWizard\WebAuthn\Format\ByteBuffer;

interface AuthenticatorAssertionResponseInterface extends AuthenticatorResponseInterface
{
    public function getAuthenticatorData(): ByteBuffer;

    public function getSignature(): ByteBuffer;

    public function getUserHandle(): ?ByteBuffer;
}

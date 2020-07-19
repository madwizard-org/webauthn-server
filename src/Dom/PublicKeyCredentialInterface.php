<?php

namespace MadWizard\WebAuthn\Dom;

use MadWizard\WebAuthn\Format\ByteBuffer;

/**
 * SPEC: 5.1. PublicKeyCredential Interface.
 */
interface PublicKeyCredentialInterface extends CredentialInterface
{
    /**
     * Returns the raw credential ID. The credential ID is used to look up credentials for use, and is therefore expected to be globally unique with high probability across all credentials of the same type, across all authenticators.
     */
    public function getRawId(): ByteBuffer;

    /**
     * This attribute contains the authenticator's response to the client’s request to either create a public key credential, or generate an authentication assertion.
     */
    public function getResponse(): AuthenticatorResponseInterface;

    public function getClientExtensionResults(): array;
}

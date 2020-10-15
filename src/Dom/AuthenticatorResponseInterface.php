<?php

namespace MadWizard\WebAuthn\Dom;

interface AuthenticatorResponseInterface
{
    /**
     * UTF-8 JSON serialization of the client data passed to the authenticator by the client in its call to either create() or get().
     */
    public function getClientDataJson(): string;

    public function getParsedClientData(): CollectedClientData;

    public function asAttestationResponse(): AuthenticatorAttestationResponseInterface;

    public function asAssertionResponse(): AuthenticatorAssertionResponseInterface;
}

<?php


namespace MadWizard\WebAuthn\Dom;

// SPEC 5.7 This is a dictionary containing the client extension input values for zero or more WebAuthn extensions, as defined in §9 WebAuthn Extensions.

class AuthenticationExtensionsClientInputs extends AbstractDictionary
{
    public function getAsArray(): array
    {
        return [];
    }
}

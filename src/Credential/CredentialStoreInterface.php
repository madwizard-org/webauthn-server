<?php


namespace MadWizard\WebAuthn\Credential;

interface CredentialStoreInterface
{
    public function findCredential(string $credentialId) : ?UserCredentialInterface;

    public function registerCredential(CredentialRegistration $credential);
}

<?php


namespace MadWizard\WebAuthn\Credential;

interface CredentialStoreInterface
{
    public function findAccountCredential(string $credentialId) : ?UserCredentialInterface;
}

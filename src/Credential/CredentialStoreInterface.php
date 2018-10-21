<?php


namespace MadWizard\WebAuthn\Credential;

interface CredentialStoreInterface
{
    public function findCredential(string $credentialId) : ?UserCredentialInterface;

    public function registerCredential(CredentialRegistration $credential);

    public function getSignatureCounter(string $credentialId) : ?int;

    public function updateSignatureCounter(string $credentialId, int $counter) : void;
}

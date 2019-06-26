<?php


namespace MadWizard\WebAuthn\Credential;

use MadWizard\WebAuthn\Exception\CredentialIdExistsException;
use MadWizard\WebAuthn\Format\ByteBuffer;

interface CredentialStoreInterface
{
    public function findCredential(string $credentialId) : ?UserCredentialInterface;

    /**
     * @param CredentialRegistration $credential
     * @return mixed
     * @throws CredentialIdExistsException
     */
    public function registerCredential(CredentialRegistration $credential);

    public function getSignatureCounter(string $credentialId) : ?int;

    public function updateSignatureCounter(string $credentialId, int $counter) : void;

    /**
     * Returns all registered credentials for a given user handle
     * @param ByteBuffer $userHandle
     * @return UserCredentialInterface[]
     */
    public function getUserCredentials(ByteBuffer $userHandle): array;
}

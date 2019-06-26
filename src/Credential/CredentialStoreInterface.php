<?php


namespace MadWizard\WebAuthn\Credential;

use http\Client\Curl\User;
use MadWizard\WebAuthn\Exception\CredentialIdExistsException;

/**
 * Interface to implement by users of this library to persist user credentials
 */
interface CredentialStoreInterface
{
    /**
     * Finds a credential by its (binary) credential id
     * Return null if no credential exists with this id.
     * @param CredentialId $credentialId
     * @return UserCredentialInterface|null
     */
    public function findCredential(CredentialId $credentialId) : ?UserCredentialInterface;

    /**
     * @param CredentialRegistration $credential
     * @return void
     * @throws CredentialIdExistsException
     */
    public function registerCredential(CredentialRegistration $credential): void;

    /**
     * Retrieve the current signature counter for a given credential id. Return null if the signature counter has not
     * been set yet or when signature counters are not supported.
     * @param CredentialId $credentialId
     * @return int|null
     */
    public function getSignatureCounter(CredentialId $credentialId) : ?int;

    /**
     * Update the signature counter for a given credential id.
     * @param CredentialId $credentialId
     * @param int $counter
     */
    public function updateSignatureCounter(CredentialId $credentialId, int $counter) : void;

    /**
     * Returns all registered credentials for a given user handle
     * @param UserHandle $userHandle
     * @return CredentialId[]
     */
    public function getUserCredentialIds(UserHandle $userHandle): array;
}

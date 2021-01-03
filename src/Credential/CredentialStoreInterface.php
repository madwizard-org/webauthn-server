<?php

namespace MadWizard\WebAuthn\Credential;

use MadWizard\WebAuthn\Exception\CredentialIdExistsException;

/**
 * Interface to implement by users of this library to persist user credentials.
 */
interface CredentialStoreInterface
{
    /**
     * Finds a credential by its (binary) credential id
     * Return null if no credential exists with this id.
     */
    public function findCredential(CredentialId $credentialId): ?UserCredentialInterface;

    /**
     * Register the given credential. You will need to store at least the credential id, user handle, public key
     * and (if you want to check signature counters) the current counter value.
     * @throws CredentialIdExistsException
     */
    public function registerCredential(CredentialRegistration $credential): void;

    /**
     * Retrieve the current signature counter for a given credential id. Return null if the signature counter has not
     * been set yet or when signature counters are not supported.
     */
    public function getSignatureCounter(CredentialId $credentialId): ?int;

    /**
     * Update the signature counter for a given credential id.
     */
    public function updateSignatureCounter(CredentialId $credentialId, int $counter): void;

    /**
     * Returns all registered credentials for a given user handle.
     *
     * @return CredentialId[]
     */
    public function getUserCredentialIds(UserHandle $userHandle): array;
}

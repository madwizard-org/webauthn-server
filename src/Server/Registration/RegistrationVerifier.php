<?php


namespace MadWizard\WebAuthn\Server\Registration;

use MadWizard\WebAuthn\Attestation\AttestationObject;
use MadWizard\WebAuthn\Attestation\AuthenticatorData;
use MadWizard\WebAuthn\Attestation\Registry\AttestationFormatRegistryInterface;
use MadWizard\WebAuthn\Dom\AuthenticatorAttestationResponseInterface;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialInterface;
use MadWizard\WebAuthn\Exception\FormatNotSupportedException;
use MadWizard\WebAuthn\Exception\VerificationException;
use MadWizard\WebAuthn\Server\AbstractVerifier;

class RegistrationVerifier extends AbstractVerifier
{
    /**
     * @var AttestationFormatRegistryInterface
     */
    private $registry;

    public function __construct(AttestationFormatRegistryInterface $registry)
    {
        $this->registry = $registry;
    }

    /**
     * @param PublicKeyCredentialInterface $credential
     * @param RegistrationContext $context
     * @return RegistrationResult
     * @throws VerificationException
     * @throws \MadWizard\WebAuthn\Exception\ParseException
     * @throws \MadWizard\WebAuthn\Exception\WebAuthnException
     */
    public function verify(PublicKeyCredentialInterface $credential, RegistrationContext $context) : RegistrationResult
    {
        // SPEC 7.1 Registering a new credential

        $response = $credential->getResponse();
        if (!($response instanceof AuthenticatorAttestationResponseInterface)) {
            throw new VerificationException('Expecting authenticator attestation response.');
        }

        // 1. Let JSONtext be the result of running UTF-8 decode on the value of response.clientDataJSON.
        // 2. Let C, the client data claimed as collected during the credential creation, be the result of running an
        //    implementation-specific JSON parser on JSONtext.
        // 3 - 6
        $this->checkClientData($response->getParsedClientData(), $context);

        // 7. Compute the hash of response.clientDataJSON using SHA-256.
        $clientDataHash = $this->getClientDataHash($response);

        // 8. Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse structure to
        //    obtain the attestation statement format fmt, the authenticator data authData, and the attestation
        //    statement attStmt.

        $attestation = new AttestationObject($response->getAttestationObject());
        $authData = new AuthenticatorData($attestation->getAuthenticatorData());

        // 9 - 11
        $this->checkAuthenticatorData($authData, $context);



        // 12. Verify that the values of the client extension outputs in clientExtensionResults and the authenticator
        //     extension outputs in the extensions in authData are as expected, considering the client extension input
        //     values that were given as the extensions option in the create() call. In particular, any extension
        //     identifier values in the clientExtensionResults and the extensions in authData MUST be also be present
        //     as extension identifier values in the extensions member of options, i.e., no extensions are present that
        //     were not requested. In the general case, the meaning of "are as expected" is specific to the
        //     Relying Party and which extensions are in use.
        //     Note: Since all extensions are OPTIONAL for both the client and the authenticator, the Relying Party MUST
        //     be prepared to handle cases where none or not all of the requested extensions were acted upon.
        // TODO:not supported yet.

        // 13. Determine the attestation statement format by performing a USASCII case-sensitive match on fmt against
        //     the set of supported WebAuthn Attestation Statement Format Identifier values.
        $format = $attestation->getFormat();

        try {
            $statement = $this->registry->createStatement($attestation);
            $verifier = $this->registry->getVerifier($attestation->getFormat());
        } catch (FormatNotSupportedException $e) {
            throw new VerificationException(sprintf("Attestation format '%s' not supported", $format), 0, $e);
        }

        // 14. Verify that attStmt is a correct attestation statement, conveying a valid attestation signature, by
        //     using the attestation statement format fmt’s verification procedure given attStmt, authData and the hash
        //     of the serialized client data computed in step 7.
        $verificationResult = $verifier->verify($statement, $authData, $clientDataHash);

        return new RegistrationResult($credential->getRawId()->getBase64Url(), $authData->getKey(), $verificationResult, $authData->getSignCount());
    }

    private function checkClientData(array $clientData, RegistrationContext $context)
    {
        $this->validateClientData($clientData);

        // 3. Verify that the value of C.type is webauthn.create.
        if ($clientData['type'] !== 'webauthn.create') {
            throw new VerificationException('Expecting type in clientDataJSON to be webauthn.create.');
        }

        // 4. Verify that the value of C.challenge matches the challenge that was sent to the authenticator
        //    in the create() call.
        if (!hash_equals($context->getChallenge()->getBase64Url(), $clientData['challenge'])) {
            throw new VerificationException('Challenge in clientDataJSON does not match the challenge in the request.');
        }

        // 5. Verify that the value of C.origin matches the Relying Party's origin.
        if (!$this->verifyOrigin($clientData['origin'], $context->getOrigin())) {
            throw new VerificationException(sprintf("Origin '%s' does not match relying party origin.", $clientData['origin']));
        }

        // 6. Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection
        //    over which the assertion was obtained. If Token Binding was used on that TLS connection, also verify that
        //    C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.
        $tokenBinding = $clientData['tokenBinding'] ?? null;
        if ($tokenBinding !== null) {
            $this->checkTokenBinding($tokenBinding);
        }
    }

    private function checkAuthenticatorData(AuthenticatorData $authData, RegistrationContext $context)
    {
        if (!$authData->hasAttestedCredentialData()) {
            throw new VerificationException('Authenticator data does not contain attested credential.');
        }


        // 9. Verify that the RP ID hash in authData is indeed the SHA-256 hash of the RP ID expected by the RP.
        if (!$this->verifyRpIdHash($authData, $context)) {
            throw new VerificationException('RP ID hash in authData does not match.');
        }

        // 10 and 11
        if (!$this->verifyUser($authData, $context)) {
            throw new VerificationException('User verification failed');
        }
    }
}

<?php


namespace MadWizard\WebAuthn\Server;

use MadWizard\WebAuthn\Credential\CredentialRegistration;
use MadWizard\WebAuthn\Credential\CredentialStoreInterface;
use MadWizard\WebAuthn\Dom\AuthenticationExtensionsClientInputs;
use MadWizard\WebAuthn\Dom\AuthenticatorAttestationResponseInterface;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialCreationOptions;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialDescriptor;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialInterface;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialParameters;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialRequestOptions;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialRpEntity;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialUserEntity;
use MadWizard\WebAuthn\Exception\CredentialIdExistsException;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Exception\UntrustedException;
use MadWizard\WebAuthn\Exception\VerificationException;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Json\JsonConverter;
use MadWizard\WebAuthn\Policy\PolicyInterface;

use MadWizard\WebAuthn\Server\Authentication\AuthenticationContext;
use MadWizard\WebAuthn\Server\Authentication\AuthenticationOptions;
use MadWizard\WebAuthn\Server\Authentication\AuthenticationRequest;
use MadWizard\WebAuthn\Server\Authentication\AuthenticationResult;
use MadWizard\WebAuthn\Server\Authentication\AuthenticationVerifier;
use MadWizard\WebAuthn\Server\Registration\RegistrationContext;
use MadWizard\WebAuthn\Server\Registration\RegistrationOptions;
use MadWizard\WebAuthn\Server\Registration\RegistrationRequest;
use MadWizard\WebAuthn\Server\Registration\RegistrationResult;
use MadWizard\WebAuthn\Server\Registration\RegistrationVerifier;

class WebAuthnServer implements ServerInterface
{
    /**
     * @var CredentialStoreInterface
     */
    private $credentialStore;

    /**
     * @var PolicyInterface
     */
    private $policy;

    public function __construct(PolicyInterface $policy, CredentialStoreInterface $credentialStore)
    {
        $this->policy = $policy;
        $this->credentialStore = $credentialStore;
    }

    public function startRegistration(RegistrationOptions $options) : RegistrationRequest
    {
        $challenge = $this->createChallenge();

        $creationOptions = new PublicKeyCredentialCreationOptions(
            PublicKeyCredentialRpEntity::fromRelyingParty($this->policy->getRelyingParty()),
            $this->createUserEntity($options->getUser()),
            $challenge,
            $this->getCredentialParameters()
        );

        $creationOptions->setAttestation($options->getAttestation());
        $creationOptions->setAuthenticatorSelection($options->getAuthenticatorSelection());
        $extensions = $options->getExtensionInputs();
        if ($extensions !== null) {
            $creationOptions->setExtensions(
                AuthenticationExtensionsClientInputs::fromArray($extensions)
            );
        }


        if ($options->getExcludeExistingCredentials()) {   // TODO default?
            $credentialIds = $this->credentialStore->getUserCredentialIds($options->getUser()->getUserHandle());
            foreach ($credentialIds as $credential) {
                $creationOptions->addExcludeCredential(
                    new PublicKeyCredentialDescriptor($credential->toBuffer())
                );
            }
        }

        $context = RegistrationContext::create($creationOptions, $this->policy);
        return new RegistrationRequest($creationOptions, $context);
    }

    /**
     * @param PublicKeyCredentialInterface|string $credential object or JSON serialized representation from the client.
     * @param RegistrationContext $context
     * @return RegistrationResult
     * @throws CredentialIdExistsException
     */
    public function finishRegistration($credential, RegistrationContext $context) : RegistrationResult
    {
        $credential = $this->convertAttestationCredential($credential);

        $verifier = new RegistrationVerifier($this->policy->getAttestationFormatRegistry());
        $registrationResult = $verifier->verify($credential, $context);

        /**
         * @var AuthenticatorAttestationResponseInterface $response
         */
        $response = $credential->getResponse();

        // 15. If validation is successful, obtain a list of acceptable trust anchors (attestation root certificates or
        //     ECDAA-Issuer public keys) for that attestation type and attestation statement format fmt, from a trusted
        //     source or from policy.

        $metadata = $this->policy->getMetadataResolver()->getMetadata($registrationResult);
        $registrationResult = $registrationResult->withMetadata($metadata);

        // 16. Assess the attestation trustworthiness using the outputs of the verification procedure in step 14,
        //     as follows:
        //       If self attestation was used, check if self attestation is acceptable under Relying Party policy.
        //       If ECDAA was used, verify that the identifier of the ECDAA-Issuer public key used is included in the
        //       set of acceptable trust anchors obtained in step 15.
        //       Otherwise, use the X.509 certificates returned by the verification procedure to verify that the
        //       attestation public key correctly chains up to an acceptable root certificate.

        try {
            $this->policy->getTrustDecisionManager()->verifyTrust($registrationResult, $metadata);
        } catch (UntrustedException $e) {
            throw new VerificationException('The attestation is not trusted: ' . $e->getReason(), 0, $e);
        }

        // 17. Check that the credentialId is not yet registered to any other user. If registration is requested for a
        //     credential that is already registered to a different user, the Relying Party SHOULD fail this
        //     registration ceremony, or it MAY decide to accept the registration, e.g. while deleting the older
        //     registration.

        // TODO

        // 18. If the attestation statement attStmt verified successfully and is found to be trustworthy, then register
        //     the new credential with the account that was denoted in the options.user passed to create(), by
        //     associating it with the credentialId and credentialPublicKey in the attestedCredentialData in authData,
        //     as appropriate for the Relying Party's system.

        // TODO

        // 19. If the attestation statement attStmt successfully verified but is not trustworthy per step 16 above,
        //     the Relying Party SHOULD fail the registration ceremony.
        //
        //    NOTE: However, if permitted by policy, the Relying Party MAY register the credential ID and credential
        //    public key but treat the credential as one with self attestation (see §6.3.3 Attestation Types).
        //    If doing so, the Relying Party is asserting there is no cryptographic proof that the public key credential
        //    has been generated by a particular authenticator model. See [FIDOSecRef] and [UAFProtocol] for a more
        //    detailed discussion.
        //
        //    Verification of attestation objects requires that the Relying Party has a trusted method of determining
        //    acceptable trust anchors in step 15 above. Also, if certificates are being used, the Relying Party MUST
        //    have access to certificate status information for the intermediate CA certificates. The Relying Party MUST
        //    also be able to build the attestation certificate chain if the client did not provide this chain in the
        //    attestation information.


        // TODO:check timeout (spec does not mention this?)

        $registration = new CredentialRegistration($registrationResult->getCredentialId(), $registrationResult->getPublicKey(), $context->getUserHandle(), $response->getAttestationObject());
        $this->credentialStore->registerCredential($registration);
        $this->credentialStore->updateSignatureCounter($registrationResult->getCredentialId(), $registrationResult->getSignatureCounter());
        return $registrationResult;
    }

    public function startAuthentication(AuthenticationOptions $options) : AuthenticationRequest
    {
        $challenge = $this->createChallenge();

        $requestOptions = new PublicKeyCredentialRequestOptions($challenge);
        $requestOptions->setRpId($this->policy->getRelyingParty()->getId());
        $requestOptions->setUserVerification($options->getUserVerification());
        $requestOptions->setTimeout($options->getTimeout());

        $this->addAllowCredentials($options, $requestOptions);

        $extensions = $options->getExtensionInputs();
        if ($extensions !== null) {
            $requestOptions->setExtensions(
                AuthenticationExtensionsClientInputs::fromArray($extensions)
            );
        }


        $context = AuthenticationContext::create($requestOptions, $this->policy);
        return new AuthenticationRequest($requestOptions, $context);
    }

    /**
     * @param PublicKeyCredentialInterface|string $credential object or JSON serialized representation from the client.
     * @param AuthenticationContext $context
     * @return AuthenticationResult
     */
    public function finishAuthentication($credential, AuthenticationContext $context) : AuthenticationResult
    {
        $credential = $this->convertAssertionCredential($credential);

        $verifier = new AuthenticationVerifier($this->credentialStore);

        $userCredential = $verifier->verifyAuthenticatonAssertion($credential, $context);

        return new AuthenticationResult($userCredential);
    }

    /**
     * @param AuthenticationOptions $options
     * @param PublicKeyCredentialRequestOptions $requestOptions
     * @throws WebAuthnException
     */
    private function addAllowCredentials(AuthenticationOptions $options, PublicKeyCredentialRequestOptions $requestOptions): void
    {
        $userHandle = $options->getAllowUserHandle();
        if ($userHandle !== null) {
            $credentialIds = $this->credentialStore->getUserCredentialIds($userHandle);
            foreach ($credentialIds as $credentialId) {
                $descriptor = new PublicKeyCredentialDescriptor($credentialId->toBuffer());
                $requestOptions->addAllowedCredential($descriptor);
            }
        }

        $credentialIds = $options->getAllowCredentials();
//        $transports = AuthenticatorTransport::allKnownTransports(); // TODO: from config
        if (count($credentialIds) > 0) {
            foreach ($credentialIds as $credential) {
                $credentialId = $credential->toBuffer();
                $descriptor = new PublicKeyCredentialDescriptor($credentialId);
//                foreach ($transports as $transport) {
//                    $descriptor->addTransport($transport);
//                }
                $requestOptions->addAllowedCredential($descriptor);
            }
        }
    }

    private function createUserEntity(UserIdentityInterface $user) : PublicKeyCredentialUserEntity
    {
        return new PublicKeyCredentialUserEntity(
            $user->getUsername(),
            $user->getUserHandle()->toBuffer(),
            $user->getDisplayName()
        );
    }

    /**
     * @return PublicKeyCredentialParameters[]
     */
    private function getCredentialParameters() : array
    {
        $parameters = [];
        $algorithms = $this->policy->getAllowedAlgorithms();
        foreach ($algorithms as $algorithm) {
            $parameters[] = new PublicKeyCredentialParameters($algorithm);
        }
        return $parameters;
    }

    private function createChallenge() : ByteBuffer
    {
        return ByteBuffer::randomBuffer($this->policy->getChallengeLength());
    }

    private function convertAttestationCredential($credential) : PublicKeyCredentialInterface
    {
        if (\is_string($credential)) {
            return JsonConverter::decodeAttestationCredential($credential);
        }

        if ($credential instanceof PublicKeyCredentialInterface) {
            return $credential;
        }

        throw new WebAuthnException('Parameter credential should be of type string or PublicKeyCredentialInterface.');
    }

    private function convertAssertionCredential($credential) : PublicKeyCredentialInterface
    {
        if (\is_string($credential)) {
            try {
                return JsonConverter::decodeAssertionCredential($credential);
            } catch (ParseException $e) {
                throw new VerificationException('Failed to parse JSON client data', 0, $e);
            }
        }

        if ($credential instanceof PublicKeyCredentialInterface) {
            return $credential;
        }

        throw new WebAuthnException('Parameter credential should be of type string or PublicKeyCredentialInterface.');
    }
}

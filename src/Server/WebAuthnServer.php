<?php


namespace MadWizard\WebAuthn\Server;

use MadWizard\WebAuthn\Attestation\Registry\AttestationFormatRegistry;
use MadWizard\WebAuthn\Attestation\Registry\AttestationFormatRegistryInterface;
use MadWizard\WebAuthn\Config\WebAuthnConfigurationInterface;
use MadWizard\WebAuthn\Credential\CredentialRegistration;
use MadWizard\WebAuthn\Credential\CredentialStoreInterface;
use MadWizard\WebAuthn\Dom\AuthenticatorTransport;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialCreationOptions;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialDescriptor;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialInterface;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialParameters;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialRequestOptions;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialUserEntity;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Exception\VerificationException;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Format\Base64UrlEncoding;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Json\JsonConverter;
use MadWizard\WebAuthn\Server\Authentication\AssertionContext;
use MadWizard\WebAuthn\Server\Authentication\AssertionVerifier;
use MadWizard\WebAuthn\Server\Authentication\AuthenticationOptions;
use MadWizard\WebAuthn\Server\Authentication\AuthenticationRequest;
use MadWizard\WebAuthn\Server\Authentication\AuthenticationResult;
use MadWizard\WebAuthn\Server\Registration\AttestationContext;
use MadWizard\WebAuthn\Server\Registration\AttestationResult;
use MadWizard\WebAuthn\Server\Registration\AttestationVerifier;
use MadWizard\WebAuthn\Server\Registration\RegistrationOptions;
use MadWizard\WebAuthn\Server\Registration\RegistrationRequest;

class WebAuthnServer
{
    /**
     * @var WebAuthnConfigurationInterface
     */
    private $config;

    /**
     * @var AttestationFormatRegistryInterface|null
     */
    private $formatRegistry;

    /**
     * @var CredentialStoreInterface
     */
    private $credentialStore;

    public function __construct(WebAuthnConfigurationInterface $config, CredentialStoreInterface $credentialStore)
    {
        $this->config = $config;
        $this->credentialStore = $credentialStore;
    }

    public function startRegistration(RegistrationOptions $options) : RegistrationRequest
    {
        $challenge = $this->createChallenge();

        $creationOptions = new PublicKeyCredentialCreationOptions(
            $this->config->getRelyingPartyEntity(),
            $this->createUserEntity($options->getUser()),
            $challenge,
            $this->getCredentialParameters()
        );

        $creationOptions->setAttestation($options->getAttestation());
        $creationOptions->setAuthenticatorSelection($options->getAuthenticatorSelection());

        $context = AttestationContext::create($creationOptions, $this->config);
        return new RegistrationRequest($creationOptions, $context);
    }

    /**
     * @param PublicKeyCredentialInterface|string $credential object or JSON serialized representation from the client.
     * @param AttestationContext $context
     * @return AttestationResult
     */
    public function finishRegistration($credential, AttestationContext $context) : AttestationResult
    {
        $credential = $this->convertAttestationCredential($credential);
        $verifier = new AttestationVerifier($this->getFormatRegistry());
        $attestationResult = $verifier->verify($credential, $context);

        // 15. If validation is successful, obtain a list of acceptable trust anchors (attestation root certificates or
        //     ECDAA-Issuer public keys) for that attestation type and attestation statement format fmt, from a trusted
        //     source or from policy. For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to
        //     obtain such information, using the aaguid in the attestedCredentialData in authData.

        // TODO

        // 16. Assess the attestation trustworthiness using the outputs of the verification procedure in step 14,
        //     as follows:
        //       If self attestation was used, check if self attestation is acceptable under Relying Party policy.
        //       If ECDAA was used, verify that the identifier of the ECDAA-Issuer public key used is included in the
        //       set of acceptable trust anchors obtained in step 15.
        //       Otherwise, use the X.509 certificates returned by the verification procedure to verify that the
        //       attestation public key correctly chains up to an acceptable root certificate.

        // TODO

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

        $registration = new CredentialRegistration($attestationResult->getCredentialId(), $attestationResult->getPublicKey(), $context->getUserHandle());
        $this->credentialStore->registerCredential($registration);
        // TODO set signature counter
        return $attestationResult;
    }

    public function startAuthentication(AuthenticationOptions $options) : AuthenticationRequest
    {
        $challenge = $this->createChallenge();

        $requestOptions = new PublicKeyCredentialRequestOptions($challenge);
        $requestOptions->setRpId($this->config->getRelyingPartyId());
        $requestOptions->setUserVerification($options->getUserVerification());
        $requestOptions->setTimeout($options->getTimeout());

        $this->addAllowCredentials($options, $requestOptions);


        $context = AssertionContext::create($requestOptions, $this->config);
        return new AuthenticationRequest($requestOptions, $context);
    }

    /**
     * @param PublicKeyCredentialInterface|string $credential object or JSON serialized representation from the client.
     * @param AssertionContext $context
     * @return AuthenticationResult
     */
    public function finishAuthentication($credential, AssertionContext $context) : AuthenticationResult
    {
        $credential = $this->convertAssertionCredential($credential);

        $verifier = new AssertionVerifier($this->credentialStore);

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
        $credentials = $options->getAllowCredentials();
        $transports = AuthenticatorTransport::allKnownTransports(); // TODO: from config
        if (count($credentials) > 0) {
            foreach ($credentials as $credential) {
                $credentialId = new ByteBuffer(Base64UrlEncoding::decode($credential->getCredentialId()));
                $descriptor = new PublicKeyCredentialDescriptor($credentialId);
                foreach ($transports as $transport) {
                    $descriptor->addTransport($transport);
                }
                $requestOptions->addAllowedCredential($descriptor);
            }
        }
    }

    private function createUserEntity(UserIdentity $user) : PublicKeyCredentialUserEntity
    {
        return new PublicKeyCredentialUserEntity(
            $user->getUsername(),
            $user->getUserHandle(),
            $user->getDisplayName()
        );
    }

    /**
     * @return PublicKeyCredentialParameters[]
     */
    private function getCredentialParameters() : array
    {
        $parameters = [];
        $algorithms = $this->config->getAllowedAlgorithms();
        foreach ($algorithms as $algorithm) {
            $parameters[] = new PublicKeyCredentialParameters($algorithm);
        }
        return $parameters;
    }

    private function createChallenge() : ByteBuffer
    {
        return ByteBuffer::randomBuffer($this->config->getChallengeLength());
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

    public function getFormatRegistry() : AttestationFormatRegistryInterface
    {
        if ($this->formatRegistry === null) {
            $this->formatRegistry = $this->createDefaultFormatRegistry();
        }

        return $this->formatRegistry;
    }

    private function createDefaultFormatRegistry() : AttestationFormatRegistry
    {
        $registry = new AttestationFormatRegistry();
        $formats = $this->config->getAttestationFormats();
        foreach ($formats as $format) {
            $registry->addFormat($format);
        }
        return $registry;
    }
}

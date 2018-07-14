<?php


namespace MadWizard\WebAuthn\Server;

use MadWizard\WebAuthn\Attestation\Registry\AttestationFormatRegistry;
use MadWizard\WebAuthn\Attestation\Registry\AttestationFormatRegistryInterface;
use MadWizard\WebAuthn\Config\WebAuthnConfiguration;
use MadWizard\WebAuthn\Credential\CredentialRegistration;
use MadWizard\WebAuthn\Credential\CredentialStoreInterface;
use MadWizard\WebAuthn\Credential\UserCredentialInterface;
use MadWizard\WebAuthn\Dom\AuthenticatorTransport;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialCreationOptions;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialDescriptor;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialInterface;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialParameters;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialRequestOptions;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialUserEntity;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Format\Base64UrlEncoding;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Json\JsonConverter;
use MadWizard\WebAuthn\Server\Authentication\AuthenticationOptions;
use MadWizard\WebAuthn\Server\Authentication\AuthenticationRequest;
use MadWizard\WebAuthn\Server\Registration\RegistrationOptions;
use MadWizard\WebAuthn\Server\Registration\RegistrationResult;
use MadWizard\WebAuthn\Server\Registration\UserIdentity;

class WebAuthnServer
{
    /**
     * @var WebAuthnConfiguration
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

    public function __construct(WebAuthnConfiguration $config, CredentialStoreInterface $credentialStore)
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

        $context = AttestationContext::create($creationOptions, $this->config);
        return new RegistrationRequest($creationOptions, $context);
    }

    /**
     * @param PublicKeyCredentialInterface|string $credential object or JSON serialized representation from the client.
     * @param AttestationContext $context
     * @return RegistrationResult
     */
    public function finishRegistration($credential, AttestationContext $context) : RegistrationResult
    {
        $credential = $this->convertAttestationCredential($credential);
        $verifier = new AttestationVerifier($this->getFormatRegistry());
        $attestationResult = $verifier->verify($credential, $context);

        $registration = new CredentialRegistration($attestationResult->getCredentialId(), $attestationResult->getPublicKey(), $context->getUserHandle());
        $this->credentialStore->registerCredential($registration);
        return new RegistrationResult($attestationResult);
    }

    public function startAuthentication(AuthenticationOptions $options) : AuthenticationRequest
    {
        $challenge = $this->createChallenge();

        $requestOptions = new PublicKeyCredentialRequestOptions($challenge);
        $requestOptions->setRpId($this->config->getRelyingPartyId());

        $this->addAllowCredentials($options, $requestOptions);


        $context = AssertionContext::create($requestOptions, $this->config);
        return new AuthenticationRequest($requestOptions, $context);
    }

    /**
     * @param PublicKeyCredentialInterface|string $credential object or JSON serialized representation from the client.
     * @param AssertionContext $context
     * @return UserCredentialInterface
     */
    public function finishAuthentication($credential, AssertionContext $context) : UserCredentialInterface
    {
        $credential = $this->convertAssertionCredential($credential);

        $verifier = new AssertionVerifier($this->credentialStore);

        $userCredential = $verifier->verifyAuthenticatonAssertion($credential, $context);

        return $userCredential;
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
            return JsonConverter::decodeAssertionCredential($credential);
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

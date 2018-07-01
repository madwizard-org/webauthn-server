<?php


namespace MadWizard\WebAuthn\Server;

use MadWizard\WebAuthn\Config\WebAuthnConfiguration;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialCreationOptions;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialInterface;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialParameters;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialUserEntity;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Json\JsonConverter;
use MadWizard\WebAuthn\Server\Registration\RegistrationOptions;
use MadWizard\WebAuthn\Server\Registration\RegistrationResult;
use MadWizard\WebAuthn\Server\Registration\UserIdentity;

class WebAuthnServer
{
    /**
     * @var WebAuthnConfiguration
     */
    private $config;

    public function __construct(WebAuthnConfiguration $config)
    {
        $this->config = $config;
    }

    public function startRegistration(UserIdentity $user, RegistrationOptions $options) : RegistrationRequest
    {
        $challenge = $this->createChallenge();

        $publicKey = new PublicKeyCredentialCreationOptions(
            $this->config->getRelyingPartyEntity(),
            $this->createUserEntity($user),
            $challenge,
            $this->getCredentialParameters()
        );

        $publicKey->setAttestation($options->getAttestation());

        $context = AttestationContext::create($publicKey, $this->config);
        return new RegistrationRequest($publicKey, $context);
    }

    /**
     * @param PublicKeyCredentialInterface|string $credential object or JSON serialized representation from the client.
     * @param AttestationContext $context
     * @return RegistrationResult
     */
    public function finishRegistration($credential, AttestationContext $context) : RegistrationResult
    {
        $credential = $this->convertAttestationCredential($credential);
        $verifier = new AttestationVerifier();
        $attestationResult = $verifier->verify($credential, $context);
        return new RegistrationResult($attestationResult);
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
     * @return PublicKeyCredentialParameters
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
}

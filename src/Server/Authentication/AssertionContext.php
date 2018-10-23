<?php


namespace MadWizard\WebAuthn\Server\Authentication;

use MadWizard\WebAuthn\Config\WebAuthnConfiguration;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialRequestOptions;
use MadWizard\WebAuthn\Exception\ConfigurationException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Server\AbstractContext;
use MadWizard\WebAuthn\Server\RequestContext;
use MadWizard\WebAuthn\Web\Origin;

class AssertionContext extends AbstractContext implements RequestContext
{
    /**
     * @var ByteBuffer[]
     */
    private $allowCredentialIds = [];

    public function __construct(ByteBuffer $challenge, Origin $origin, string $rpId)
    {
        parent::__construct($challenge, $origin, $rpId);
    }

    public function addAllowCredentialId(ByteBuffer $buffer)
    {
        $this->allowCredentialIds[] = $buffer;
    }

    public static function create(PublicKeyCredentialRequestOptions $options, WebAuthnConfiguration $configuration) : self
    {
        $origin = $configuration->getRelyingPartyOrigin();
        if ($origin === null) {
            throw new ConfigurationException('Could not determine relying party origin.');
        }

        $rpId = $options->getRpId();
        if ($rpId === null) {
            $rpId = $configuration->getEffectiveRelyingPartyId();
        }

        $context = new self($options->getChallenge(), $origin, $rpId);

        $allowCredentials = $options->getAllowCredentials();
        if ($allowCredentials !== null) {
            foreach ($allowCredentials as $credential) {
                $context->addAllowCredentialId($credential->getId());
            }
        }
        return $context;
    }

    /**
     * @return ByteBuffer[]
     */
    public function getAllowCredentialIds() : array
    {
        return $this->allowCredentialIds;
    }

    public function serialize()
    {
        return \serialize([$this->allowCredentialIds, parent::serialize()]);
    }

    public function unserialize($serialized)
    {
        [$this->allowCredentialIds, $parentStr] = \unserialize((string) $serialized);
        parent::unserialize($parentStr);
    }
}

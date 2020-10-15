<?php

namespace MadWizard\WebAuthn\Dom;

use MadWizard\WebAuthn\Exception\DataValidationException;
use MadWizard\WebAuthn\Exception\VerificationException;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Format\DataValidator;

final class CollectedClientData
{
    /**
     * @var string
     */
    private $type;

    /**
     * @var string
     */
    private $challenge;

    /**
     * @var string
     */
    private $origin;

    /**
     * @var TokenBinding|null
     */
    private $tokenBinding;

    public function __construct(string $type, string $challenge, string $origin)
    {
        $this->type = $type;
        $this->challenge = $challenge;
        $this->origin = $origin;
    }

    public function withTokenBinding(TokenBinding $tokenBinding): self
    {
        $copy = clone $this;
        $copy->tokenBinding = $tokenBinding;
        return $copy;
    }

    public static function fromJson(array $clientDataJson): self
    {
        try {
            DataValidator::checkArray(
                $clientDataJson,
                [
                    'type' => 'string',
                    'challenge' => 'string',
                    'origin' => 'string',
                    'tokenBinding' => '?array',
                ],
                false
            );
        } catch (DataValidationException $e) {
            throw new VerificationException('Missing data or unexpected type in clientDataJSON', 0, $e);
        }

        $clientData = new self(
            $clientDataJson['type'],
            $clientDataJson['challenge'],
            $clientDataJson['origin']
        );
        $tokenBindingJson = $clientDataJson['tokenBinding'] ?? null;

        if ($tokenBindingJson !== null) {
            $clientData = $clientData->withTokenBinding(self::parseTokenBinding($tokenBindingJson));
        }
        return $clientData;
    }

    private static function parseTokenBinding(array $tokenBindingJson): TokenBinding
    {
        try {
            DataValidator::checkArray(
                $tokenBindingJson,
                [
                    'status' => 'string',
                    'id' => '?string',
                ],
                false
            );
        } catch (DataValidationException $e) {
            throw new VerificationException('Missing data or unexpected type in tokenBinding', 0, $e);
        }

        try {
            $id = null;
            $encodedId = $tokenBindingJson['id'] ?? null;
            if ($encodedId !== null) {
                $id = ByteBuffer::fromBase64Url($encodedId);
            }
            return new TokenBinding($tokenBindingJson['status'], $id);
        } catch (WebAuthnException $e) {
            throw new VerificationException(sprintf('Invalid token binding: %s', $e->getMessage()), 0, $e);
        }
    }

    public function getType(): string
    {
        return $this->type;
    }

    public function getChallenge(): string
    {
        return $this->challenge;
    }

    public function getOrigin(): string
    {
        return $this->origin;
    }

    public function getTokenBinding(): ?TokenBinding
    {
        return $this->tokenBinding;
    }
}

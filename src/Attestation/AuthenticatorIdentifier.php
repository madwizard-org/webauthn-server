<?php

namespace MadWizard\WebAuthn\Attestation;

class AuthenticatorIdentifier
{
    public const TYPE_AAGUID = 'aaguid';

    public const TYPE_AAID = 'aaid';

    public const TYPE_PUBLICKEYID = 'publickeyid';

    /**
     * @var string
     */
    private $id;

    /**
     * @var string
     */
    private $type;

    public function __construct(string $id, string $type)
    {
        $this->id = $id;
        $this->type = $type;
    }

    public function getId(): string
    {
        return $this->id;
    }

    public function getType(): string
    {
        return $this->type;
    }
}

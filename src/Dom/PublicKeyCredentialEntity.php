<?php


namespace MadWizard\WebAuthn\Dom;

class PublicKeyCredentialEntity extends AbstractDictionary
{
    /**
     * @var string
     */
    protected $name;

    // TODO: NOTE: icon member not implemented

    public function __construct(string $name)
    {
        $this->name = $name;
    }

    /**
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * @param string $name
     */
    public function setName(string $name): void
    {
        $this->name = $name;
    }

    public function getAsArray(): array
    {
        return [
            'name' => $this->name
        ];
    }
}

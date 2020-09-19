<?php

namespace MadWizard\WebAuthn\Server\Registration;

use MadWizard\WebAuthn\Dom\PublicKeyCredentialCreationOptions;
use MadWizard\WebAuthn\Json\JsonConverter;

final class RegistrationRequest
{
    /**
     * @var PublicKeyCredentialCreationOptions
     */
    private $creationOptions;

    /**
     * @var RegistrationContext
     */
    private $context;

    public function __construct(PublicKeyCredentialCreationOptions $creationOptions, RegistrationContext $context)
    {
        $this->creationOptions = $creationOptions;
        $this->context = $context;
    }

    public function getClientOptions(): PublicKeyCredentialCreationOptions
    {
        return $this->creationOptions;
    }

    public function getClientOptionsJson(): array
    {
        return JsonConverter::encodeDictionary($this->creationOptions);
    }

    public function getContext(): RegistrationContext
    {
        return $this->context;
    }
}

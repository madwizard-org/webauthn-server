<?php


namespace MadWizard\WebAuthn\Server\Authentication;

use MadWizard\WebAuthn\Dom\PublicKeyCredentialRequestOptions;
use MadWizard\WebAuthn\Json\JsonConverter;

class AuthenticationRequest
{
    /**
     * @var PublicKeyCredentialRequestOptions
     */
    private $requestOptions;

    /**
     * @var AssertionContext
     */
    private $context;

    public function __construct(PublicKeyCredentialRequestOptions $requestOptions, AssertionContext $context)
    {
        $this->requestOptions = $requestOptions;
        $this->context = $context;
    }

    public function getClientOptions() : PublicKeyCredentialRequestOptions
    {
        return $this->requestOptions;
    }

    public function getClientOptionsJson(): array
    {
        return JsonConverter::encodeDictionary($this->requestOptions);
    }

    public function getContext() : AssertionContext
    {
        return $this->context;
    }
}

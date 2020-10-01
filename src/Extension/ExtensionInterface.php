<?php

namespace MadWizard\WebAuthn\Extension;

interface ExtensionInterface
{
    public const OPERATION_REGISTRATION = 'registration';

    public const OPERATION_AUTHENTICATION = 'authentication';

    public function getIdentifier(): string;

    public function parseResponse(ExtensionResponseInterface $extensionResponse): ExtensionOutputInterface;

    public function processExtension(ExtensionInputInterface $input, ExtensionOutputInterface $output, ExtensionProcessingContext $context): void;
}

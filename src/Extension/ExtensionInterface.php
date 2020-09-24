<?php

namespace MadWizard\WebAuthn\Extension;

interface ExtensionInterface
{
    public const OPERATION_REGISTRATION = 'registration';

    public const OPERATION_AUTHENTICATION = 'authentication';

    public function getIdentifier(): string;

    public function parseResponse(ExtensionResponseInterface $extensionResponse): ExtensionOutputInterface;

    /**
     * @return string[]
     *
     * @see self::OPERATION_REGISTRATION
     * @see self::OPERATION_AUTHENTICATION
     */
    public function getSupportedOperations(): array;

    public function processExtension(ExtensionInputInterface $input, ExtensionOutputInterface $output, ExtensionProcessingContext $context): void;
}

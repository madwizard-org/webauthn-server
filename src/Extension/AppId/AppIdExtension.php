<?php

namespace MadWizard\WebAuthn\Extension\AppId;

use MadWizard\WebAuthn\Exception\ExtensionException;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Extension\AbstractExtension;
use MadWizard\WebAuthn\Extension\ExtensionInputInterface;
use MadWizard\WebAuthn\Extension\ExtensionOutputInterface;
use MadWizard\WebAuthn\Extension\ExtensionProcessingContext;
use MadWizard\WebAuthn\Extension\ExtensionResponseInterface;

class AppIdExtension extends AbstractExtension
{
    public function __construct()
    {
        parent::__construct('appid', [self::OPERATION_AUTHENTICATION]);
    }

    public function parseResponse(ExtensionResponseInterface $extensionResponse): ExtensionOutputInterface
    {
        $extensionOutput = $extensionResponse->getClientExtensionOutput();
        if (!is_bool($extensionOutput)) {
            throw new ParseException('Expecting boolean value in appid extension output.');
        }

        return new AppIdExtensionOutput($extensionOutput);
    }

    public function processExtension(ExtensionInputInterface $input, ExtensionOutputInterface $output, ExtensionProcessingContext $context): void
    {
        if (!$input instanceof AppIdExtensionInput) {
            throw new ExtensionException('Expecting appid extension input to be AppIdExtensionInput.');
        }
        if (!$output instanceof AppIdExtensionOutput) {
            throw new ExtensionException('Expecting appid extension output to be AppIdExtensionOutput.');
        }
        // SPEC: Client extension output: If true, the AppID was used and thus, when verifying an assertion,
        // the Relying Party MUST expect the rpIdHash to be the hash of the AppID, not the RP ID.
        if ($output->getAppIdUsed()) {
            $context->setOverruledRpId($input->getAppId());
        }
    }
}

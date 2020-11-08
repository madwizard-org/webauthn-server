<?php

namespace MadWizard\WebAuthn\Server;

use MadWizard\WebAuthn\Attestation\AuthenticatorData;
use MadWizard\WebAuthn\Dom\AuthenticatorResponseInterface;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialInterface;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Exception\VerificationException;
use MadWizard\WebAuthn\Extension\ExtensionProcessingContext;
use MadWizard\WebAuthn\Extension\ExtensionRegistryInterface;
use MadWizard\WebAuthn\Extension\ExtensionResponse;
use MadWizard\WebAuthn\Format\CborMap;
use MadWizard\WebAuthn\Web\Origin;

abstract class AbstractVerifier
{
    /**
     * @var ExtensionRegistryInterface
     */
    protected $extensionRegistry;

    public function __construct(ExtensionRegistryInterface $extensionRegistry)
    {
        $this->extensionRegistry = $extensionRegistry;
    }

    // TODO: move?
    protected function verifyOrigin(string $origin, Origin $rpOrigin): bool
    {
        try {
            $clientOrigin = Origin::parse($origin);
        } catch (ParseException $e) {
            throw new VerificationException('Client has specified an invalid origin.', 0, $e);
        }

        return $clientOrigin->equals($rpOrigin);
    }

    protected function verifyRpIdHash(AuthenticatorData $authData, AbstractContext $context, ExtensionProcessingContext $extensionContext): bool
    {
        $effectiveRpId = $context->getRpId();
        $overruledRpId = $extensionContext->getOverruledRpId();
        if ($overruledRpId !== null) {
            $effectiveRpId = $overruledRpId;
        }
        $validHash = hash('sha256', $effectiveRpId, true);
        return hash_equals($validHash, $authData->getRpIdHash()->getBinaryString());
    }

    protected function verifyUser(AuthenticatorData $authData, AbstractContext $context): bool
    {
        // Reg 10/11, Auth 12/13

        // Reg 7.1 #10 Verify that the User Present bit of the flags in authData is set.
        // Note: isUserPresenceRequired is true by default to conform to the WebAuthn spec.
        // It can be set to false manually when required to pass full FIDO2 compliance, which conflicts the
        // WebAuthn spec.
        // @see https://github.com/fido-alliance/conformance-tools-issues/issues/434
        if (!$authData->isUserPresent() && $context->isUserPresenceRequired()) {
            return false;
        }

        if ($context->isUserVerificationRequired()) {
            // Reg 7.1 #11 If user verification is required for this registration, verify that the User Verified bit of the
            // flags in authData is set.
            return $authData->isUserVerified();
        }

        return true;
    }

    protected function getClientDataHash(AuthenticatorResponseInterface $response): string
    {
        return hash('sha256', $response->getClientDataJson(), true);
    }

    protected function processExtensions(PublicKeyCredentialInterface $credential, AuthenticatorData $authData, AbstractContext $operationContext, string $operation): ExtensionProcessingContext
    {
        $authExtensionOutputs = $authData->hasExtensionData() ? $authData->getExtensionData() : new CborMap();

        // TODO: check for unwanted $authExtensionOutputs
        $extensionContext = new ExtensionProcessingContext($operation);

        $results = $credential->getClientExtensionResults();
        $inputs = [];
        foreach ($operationContext->getExtensionInputs() as $input) {
            $inputs[$input->getIdentifier()] = $input;
        }

        foreach ($results as $id => $result) {
            $input = $inputs[$id] ?? null;
            if ($input === null) {
                throw new VerificationException(sprintf('Extension "%s" is present in clientExtensionResults but was not used in the input.', $id));
            }
            $extension = $this->extensionRegistry->getExtension($id);

            $extensionResponse = new ExtensionResponse($id);
            $extensionResponse->setClientExtensionOutput($result);
            if ($authExtensionOutputs->has($id)) {
                $extensionResponse->setAuthenticatorExtensionOutput($authExtensionOutputs->get($id));
            }
            $output = $extension->parseResponse($extensionResponse);
            $extensionContext->addOutput($output);
            $extension->processExtension($input, $output, $extensionContext);
        }

        return $extensionContext;
    }
}

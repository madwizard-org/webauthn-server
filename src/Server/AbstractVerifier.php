<?php

namespace MadWizard\WebAuthn\Server;

use MadWizard\WebAuthn\Attestation\AuthenticatorData;
use MadWizard\WebAuthn\Dom\AuthenticatorResponseInterface;
use MadWizard\WebAuthn\Dom\TokenBindingStatus;
use MadWizard\WebAuthn\Exception\DataValidationException;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Exception\VerificationException;
use MadWizard\WebAuthn\Format\DataValidator;
use MadWizard\WebAuthn\Web\Origin;

class AbstractVerifier
{
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

    protected function verifyRpIdHash(AuthenticatorData $authData, AbstractContext $context)
    {
        // TODO: lowercase? spec?
        $validHash = hash('sha256', $context->getRpId(), true);
        return hash_equals($validHash, $authData->getRpIdHash()->getBinaryString());
    }

    protected function verifyUser(AuthenticatorData $authData, AbstractContext $context)
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

    protected function validateClientData(array $clientData)
    {
        try {
            DataValidator::checkTypes(
                $clientData,
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
    }

    protected function checkTokenBinding(array $tokenBinding)
    {
        try {
            DataValidator::checkTypes(
                $tokenBinding,
                [
                    'status' => 'string',
                    'id' => '?string',
                ],
                false
            );
        } catch (DataValidationException $e) {
            throw new VerificationException('Missing data or unexpected type in tokenBinding', 0, $e);
        }

        $status = $tokenBinding['status'];
        // $id = $tokenBinding['id'] ?? null;

        if (!TokenBindingStatus::isValidValue($status)) {
            throw new VerificationException(sprintf("Token binding status '%s' is invalid", $status));
        }
        // NOTE: token binding is currently not supported by this library
        if ($status === TokenBindingStatus::PRESENT) {
            throw new VerificationException('Token binding is not supported by the relying party.');
        }
    }

    protected function getClientDataHash(AuthenticatorResponseInterface $response)
    {
        return hash('sha256', $response->getClientDataJson(), true);
    }
}

<?php


namespace MadWizard\WebAuthn\Server;

use MadWizard\WebAuthn\Attestation\AuthenticatorData;
use MadWizard\WebAuthn\Dom\AuthenticatorResponseInterface;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Exception\VerificationException;
use MadWizard\WebAuthn\Web\Origin;

class AbstractVerifier
{
    public function __construct()
    {
    }

    // TODO: move?
    protected function verifyOrigin(string $origin, Origin $rpOrigin) : bool
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
        // Reg 10/12, Auth 12/13
        if ($context->isUserVerificationRequired()) {
            // If user verification is required for this registration, verify that the User Verified bit of the
            //     flags in authData is set.
            return $authData->isUserVerified();
        }

        // If user verification is not required for this registration, verify that the User Present bit of the
        // flags in authData is set.
        return $authData->isUserPresent();
    }

    protected function getClientDataHash(AuthenticatorResponseInterface $response)
    {
        return hash('sha256', $response->getClientDataJSON(), true);
    }
}

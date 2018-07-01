<?php


namespace MadWizard\WebAuthn\Server;

use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Exception\VerificationException;
use MadWizard\WebAuthn\Web\Origin;

class AbstractVerifier
{
    public function __construct()
    {
    }

    protected function verifyOrigin(string $origin, Origin $rpOrigin) : bool
    {
        try {
            $clientOrigin = Origin::parse($origin);
        } catch (ParseException $e) {
            throw new VerificationException('Client has specified an invalid origin.', 0, $e);
        }

        return $clientOrigin->equals($rpOrigin);
    }
}

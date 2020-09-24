<?php

namespace MadWizard\WebAuthn\Tests\Attestation;

use MadWizard\WebAuthn\Attestation\AuthenticatorData;
use MadWizard\WebAuthn\Attestation\Verifier\AttestationVerifierInterface;
use MadWizard\WebAuthn\Dom\AuthenticatorAttestationResponseInterface;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Json\JsonConverter;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;
use PHPUnit\Framework\TestCase;

abstract class VerifierTest extends TestCase
{
    protected function getFidoResponse(string $name): AuthenticatorAttestationResponseInterface
    {
        $json = FixtureHelper::getJsonFixture('fido2-helpers/attestation.json');
        $message = $json[$name];
        $message['type'] = 'public-key';
        $credential = JsonConverter::decodeAttestation($message);

        return $credential->getResponse()->asAttestationResponse();
    }

    protected function getTestAuthenticatorData(): AuthenticatorData
    {
        return new AuthenticatorData(
            new ByteBuffer(str_repeat('x', 32) . "\x01" . "\x11\x22\x33\x44")
        );
    }

    protected function checkFormat(AttestationVerifierInterface $verifier, string $attestationClass)
    {
        $format = $verifier->getSupportedFormat();
        self::assertSame($attestationClass::FORMAT_ID, $format->getFormatId());
        self::assertSame($verifier, $format->getVerifier());
    }
}

<?php

namespace MadWizard\WebAuthn\Tests\Attestation;

use MadWizard\WebAuthn\Attestation\AttestationType;
use MadWizard\WebAuthn\Attestation\AuthenticatorData;
use MadWizard\WebAuthn\Attestation\Statement\AndroidSafetyNetAttestationStatement;
use MadWizard\WebAuthn\Attestation\Verifier\AndroidSafetyNetAttestationVerifier;
use MadWizard\WebAuthn\Format\Base64UrlEncoding;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;
use PHPUnit\Framework\TestCase;

class AndroidSafetyNetStatementVerifierTest extends TestCase
{
    public function testSafetyNet()
    {
        $plain = FixtureHelper::getFidoTestPlain('challengeResponseAttestationSafetyNetMsgB64Url');
        $attObj = FixtureHelper::getFidoTestObject('challengeResponseAttestationSafetyNetMsgB64Url');

        $hash = hash('sha256', Base64UrlEncoding::decode($plain['response']['clientDataJSON']), true);
        $statement = new AndroidSafetyNetAttestationStatement($attObj);

        $verifier = new AndroidSafetyNetAttestationVerifier();
        $result = $verifier->verify($statement, new AuthenticatorData($attObj->getAuthenticatorData()), $hash);

        $this->assertSame(AttestationType::BASIC, $result->getAttestationType());
        // TODO: check trust path
    }
}

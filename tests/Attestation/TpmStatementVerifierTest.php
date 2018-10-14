<?php

namespace MadWizard\WebAuthn\Tests\Attestation;

use MadWizard\WebAuthn\Attestation\AttestationType;
use MadWizard\WebAuthn\Attestation\AuthenticatorData;
use MadWizard\WebAuthn\Attestation\Statement\TpmAttestationStatement;
use MadWizard\WebAuthn\Attestation\Verifier\TpmStatementVerifier;
use MadWizard\WebAuthn\Format\Base64UrlEncoding;
use MadWizard\WebAuthn\Pki\CertificateParser;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;
use PHPUnit\Framework\TestCase;

class TpmStatementVerifierTest extends TestCase
{
    public function testTpm()
    {
        $this->markTestIncomplete(
            'not complete yet'
        );

        $plain = FixtureHelper::getFidoTestPlain('challengeResponseAttestationTpmB64UrlMsg');
        $attObj = FixtureHelper::getFidoTestObject('challengeResponseAttestationTpmB64UrlMsg');

        $hash = hash('sha256', Base64UrlEncoding::decode($plain['response']['clientDataJSON']), true);
        $statement = new TpmAttestationStatement($attObj);

        $verifier = new TpmStatementVerifier(new CertificateParser());
        $result = $verifier->verify($statement, new AuthenticatorData($attObj->getAuthenticatorData()), $hash);

        $this->assertSame(AttestationType::BASIC, $result->getAttestationType());
        // TODO: check trust path
    }
}

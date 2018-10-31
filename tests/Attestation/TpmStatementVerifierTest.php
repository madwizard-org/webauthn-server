<?php

namespace MadWizard\WebAuthn\Tests\Attestation;

use MadWizard\WebAuthn\Attestation\AttestationType;
use MadWizard\WebAuthn\Attestation\AuthenticatorData;
use MadWizard\WebAuthn\Attestation\Statement\TpmAttestationStatement;
use MadWizard\WebAuthn\Attestation\Verifier\TpmAttestationVerifier;
use MadWizard\WebAuthn\Format\Base64UrlEncoding;
use MadWizard\WebAuthn\Pki\CertificateParser;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;
use PHPUnit\Framework\TestCase;

class TpmStatementVerifierTest extends TestCase
{
    public function testTpm()
    {
        $plain = FixtureHelper::getFidoTestPlain('challengeResponseAttestationTpmB64UrlMsg');
        $attObj = FixtureHelper::getFidoTestObject('challengeResponseAttestationTpmB64UrlMsg');

        $hash = hash('sha256', Base64UrlEncoding::decode($plain['response']['clientDataJSON']), true);
        $statement = new TpmAttestationStatement($attObj);

        $verifier = new TpmAttestationVerifier(new CertificateParser());
        $result = $verifier->verify($statement, new AuthenticatorData($attObj->getAuthenticatorData()), $hash);

        $this->assertSame(AttestationType::ATT_CA, $result->getAttestationType());
        // TODO: check trust path
    }
}

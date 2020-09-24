<?php

namespace MadWizard\WebAuthn\Tests\Attestation;

use MadWizard\WebAuthn\Attestation\AttestationType;
use MadWizard\WebAuthn\Attestation\AuthenticatorData;
use MadWizard\WebAuthn\Attestation\Statement\TpmAttestationStatement;
use MadWizard\WebAuthn\Attestation\Verifier\TpmAttestationVerifier;
use MadWizard\WebAuthn\Format\Base64UrlEncoding;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;

class TpmStatementVerifierTest extends VerifierTest
{
    /**
     * @var TpmAttestationVerifier
     */
    private $verifier;

    protected function setUp(): void
    {
        $this->verifier = new TpmAttestationVerifier();
    }

    public function testTpm()
    {
        $plain = FixtureHelper::getFidoTestPlain('challengeResponseAttestationTpmB64UrlMsg');
        $attObj = FixtureHelper::getFidoTestObject('challengeResponseAttestationTpmB64UrlMsg');

        $hash = hash('sha256', Base64UrlEncoding::decode($plain['response']['clientDataJSON']), true);
        $statement = new TpmAttestationStatement($attObj);

        $result = $this->verifier->verify($statement, new AuthenticatorData($attObj->getAuthenticatorData()), $hash);

        self::assertSame(AttestationType::ATT_CA, $result->getAttestationType());
        // TODO: check trust path
    }

    public function testCreateFormat()
    {
        $this->checkFormat($this->verifier, TpmAttestationStatement::class);
    }
}

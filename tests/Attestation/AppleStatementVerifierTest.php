<?php

namespace MadWizard\WebAuthn\Tests\Attestation;

use MadWizard\WebAuthn\Attestation\AttestationObject;
use MadWizard\WebAuthn\Attestation\AttestationType;
use MadWizard\WebAuthn\Attestation\AuthenticatorData;
use MadWizard\WebAuthn\Attestation\Statement\AppleAttestationStatement;
use MadWizard\WebAuthn\Attestation\TrustPath\CertificateTrustPath;
use MadWizard\WebAuthn\Attestation\Verifier\AppleAttestationVerifier;
use MadWizard\WebAuthn\Format\Base64UrlEncoding;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;

class AppleStatementVerifierTest extends VerifierTest
{
    /**
     * @var AppleStatementVerifierTest
     */
    private $verifier;

    protected function setUp(): void
    {
        $this->verifier = new AppleAttestationVerifier();
    }

    public function testAndroidKey()
    {
        $clientResponse = FixtureHelper::getTestPlain('apple');
        $chains = FixtureHelper::getTestPlain('certChains');
        $attObj = AttestationObject::parse(ByteBuffer::fromBase64Url($clientResponse['response']['attestationObject']));

        $hash = hash('sha256', Base64UrlEncoding::decode($clientResponse['response']['clientDataJSON']), true);
        $statement = new AppleAttestationStatement($attObj);

        $result = $this->verifier->verify($statement, new AuthenticatorData($attObj->getAuthenticatorData()), $hash);

        self::assertSame(AttestationType::ANON_CA, $result->getAttestationType());

        /**
         * @var CertificateTrustPath $trustPath
         */
        $trustPath = $result->getTrustPath();
        self::assertInstanceOf(CertificateTrustPath::class, $trustPath);
        self::assertSame($chains['apple'], $trustPath->asPemList());
    }

    public function testCreateFormat()
    {
        $this->checkFormat($this->verifier, AppleAttestationStatement::class);
    }
}

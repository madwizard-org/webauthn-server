<?php

namespace MadWizard\WebAuthn\Tests\Attestation;

use MadWizard\WebAuthn\Attestation\AttestationObject;
use MadWizard\WebAuthn\Attestation\AttestationType;
use MadWizard\WebAuthn\Attestation\AuthenticatorData;
use MadWizard\WebAuthn\Attestation\Statement\AndroidSafetyNetAttestationStatement;
use MadWizard\WebAuthn\Attestation\TrustPath\CertificateTrustPath;
use MadWizard\WebAuthn\Attestation\Verifier\AndroidSafetyNetAttestationVerifier;
use MadWizard\WebAuthn\Exception\VerificationException;
use MadWizard\WebAuthn\Format\Base64UrlEncoding;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;

class AndroidSafetyNetStatementVerifierTest extends VerifierTest
{
    /**
     * @var AndroidSafetyNetAttestationVerifier
     */
    private $verifier;

    protected function setUp(): void
    {
        $this->verifier = new AndroidSafetyNetAttestationVerifier();
    }

    public function testSafetyNet()
    {
        $clientResponse = FixtureHelper::getTestPlain('android-safetynet-clientresponse');
        $chains = FixtureHelper::getTestPlain('certChains');
        $attObj = AttestationObject::parse(ByteBuffer::fromBase64Url($clientResponse['response']['attestationObject']));

        $hash = hash('sha256', Base64UrlEncoding::decode($clientResponse['response']['clientDataJSON']), true);
        $statement = new AndroidSafetyNetAttestationStatement($attObj);

        $this->verifier->useFixedTimestamp(1541336750000);

        $result = $this->verifier->verify($statement, new AuthenticatorData($attObj->getAuthenticatorData()), $hash);

        self::assertSame(AttestationType::BASIC, $result->getAttestationType());

        /**
         * @var CertificateTrustPath $trustPath
         */
        $trustPath = $result->getTrustPath();
        self::assertInstanceOf(CertificateTrustPath::class, $trustPath);
        self::assertSame($chains['android-safetynet'], $trustPath->asPemList());
    }

    public function testCtsProfileMatch()
    {
        $plain = FixtureHelper::getFidoTestPlain('challengeResponseAttestationSafetyNetMsgB64Url');
        $attObj = FixtureHelper::getFidoTestObject('challengeResponseAttestationSafetyNetMsgB64Url');

        $hash = hash('sha256', Base64UrlEncoding::decode($plain['response']['clientDataJSON']), true);
        $statement = new AndroidSafetyNetAttestationStatement($attObj);

        $this->verifier->useFixedTimestamp(1532716642000); // Overide current time to pass validation

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessageMatches('~Attestation should have ctsProfileMatch set to true~i');
        $this->verifier->verify($statement, new AuthenticatorData($attObj->getAuthenticatorData()), $hash);
    }

    public function testCreateFormat()
    {
        $this->checkFormat($this->verifier, AndroidSafetyNetAttestationStatement::class);
    }
}

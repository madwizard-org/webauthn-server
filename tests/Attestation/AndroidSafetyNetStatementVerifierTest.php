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
use PHPUnit\Framework\TestCase;

class AndroidSafetyNetStatementVerifierTest extends TestCase
{
    public function testSafetyNet()
    {
        $clientResponse = FixtureHelper::getTestPlain('android-safetynet-clientresponse');
        $chains = FixtureHelper::getTestPlain('certChains');
        $attObj = new AttestationObject(ByteBuffer::fromBase64Url($clientResponse['response']['attestationObject']));

        $hash = hash('sha256', Base64UrlEncoding::decode($clientResponse['response']['clientDataJSON']), true);
        $statement = new AndroidSafetyNetAttestationStatement($attObj);

        $verifier = new class extends AndroidSafetyNetAttestationVerifier {
            protected function getMsTimestamp(): float
            {
                return 1541336750000; // Overide current time to pass validation
            }
        };
        $result = $verifier->verify($statement, new AuthenticatorData($attObj->getAuthenticatorData()), $hash);

        $this->assertSame(AttestationType::BASIC, $result->getAttestationType());


        /**
         * @var CertificateTrustPath $trustPath
         */
        $trustPath = $result->getTrustPath();
        $this->assertInstanceOf(CertificateTrustPath::class, $trustPath);
        $this->assertSame($chains['android-safetynet'], $trustPath->getCertificates());
    }

    public function testCtsProfileMatch()
    {
        $plain = FixtureHelper::getFidoTestPlain('challengeResponseAttestationSafetyNetMsgB64Url');
        $attObj = FixtureHelper::getFidoTestObject('challengeResponseAttestationSafetyNetMsgB64Url');

        $hash = hash('sha256', Base64UrlEncoding::decode($plain['response']['clientDataJSON']), true);
        $statement = new AndroidSafetyNetAttestationStatement($attObj);

        $verifier = new class extends AndroidSafetyNetAttestationVerifier {
            protected function getMsTimestamp(): float
            {
                return 1532716642000; // Overide current time to pass validation
            }
        };

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessageRegExp('~Attestation should have ctsProfileMatch set to true~i');
        $verifier->verify($statement, new AuthenticatorData($attObj->getAuthenticatorData()), $hash);
    }
}

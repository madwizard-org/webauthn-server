<?php

namespace MadWizard\WebAuthn\Tests\Attestation;

use MadWizard\WebAuthn\Attestation\AttestationObject;
use MadWizard\WebAuthn\Attestation\AttestationType;
use MadWizard\WebAuthn\Attestation\AuthenticatorData;
use MadWizard\WebAuthn\Attestation\Statement\AndroidKeyAttestationStatement;
use MadWizard\WebAuthn\Attestation\TrustPath\CertificateTrustPath;
use MadWizard\WebAuthn\Attestation\Verifier\AndroidKeyAttestationVerifier;
use MadWizard\WebAuthn\Format\Base64UrlEncoding;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;
use PHPUnit\Framework\TestCase;

class AndroidKeyStatementVerifierTest extends TestCase
{
    public function testAndroidKey()
    {
        $clientResponse = FixtureHelper::getTestPlain('android-key-clientresponse');
        $chains = FixtureHelper::getTestPlain('certChains');
        $attObj = new AttestationObject(ByteBuffer::fromBase64Url($clientResponse['response']['attestationObject']));

        $hash = hash('sha256', Base64UrlEncoding::decode($clientResponse['response']['clientDataJSON']), true);
        $statement = new AndroidKeyAttestationStatement($attObj);

        $verifier = new AndroidKeyAttestationVerifier();
        $result = $verifier->verify($statement, new AuthenticatorData($attObj->getAuthenticatorData()), $hash);

        $this->assertSame(AttestationType::BASIC, $result->getAttestationType());

        /**
         * @var CertificateTrustPath $trustPath
         */
        $trustPath = $result->getTrustPath();
        $this->assertInstanceOf(CertificateTrustPath::class, $trustPath);
        $this->assertSame($chains['android-key'], $trustPath->asPemList());
    }
}

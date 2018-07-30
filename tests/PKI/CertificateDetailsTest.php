<?php

namespace MadWizard\WebAuthn\Tests\PKI;

use MadWizard\WebAuthn\Dom\COSEAlgorithm;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\PKI\CertificateDetails;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;
use PHPUnit\Framework\TestCase;
use function hex2bin;

class CertificateDetailsTest extends TestCase
{
    private function getData(string $name) : string
    {
        $json = FixtureHelper::getJsonFixture('PKI/testcertificates.json');
        return $json[$name];
    }

    public function testVersion1()
    {
        $pem = $this->getData('v1Certificate');
        $cert = CertificateDetails::fromPEM($pem);
        $this->assertSame(CertificateDetails::VERSION_1, $cert->getCertificateVersion());
        $this->assertNull($cert->isCA());
        $this->assertNull($cert->getFidoAaguidExtensionValue());
    }

    public function testRSASignature()
    {
        $pem = $this->getData('v1Certificate');
        $cert = CertificateDetails::fromPEM($pem);
        $this->assertTrue($cert->verifySignature('testdata', hex2bin($this->getData('v1SignedData')), COSEAlgorithm::RS256));
        $this->assertFalse($cert->verifySignature('testfail', hex2bin($this->getData('v1SignedData')), COSEAlgorithm::RS256));
    }

    public function testECSignature()
    {
        $pem = $this->getData('ecCertificate');
        $cert = CertificateDetails::fromPEM($pem);
        $this->assertTrue($cert->verifySignature('testmessage', hex2bin($this->getData('ecSignedData')), COSEAlgorithm::ES256));
        $this->assertFalse($cert->verifySignature('testfail', hex2bin($this->getData('ecSignedData')), COSEAlgorithm::ES256));
    }

    public function testUnsupportedAlgorithm()
    {
        $pem = $this->getData('ecCertificate');
        $cert = CertificateDetails::fromPEM($pem);

        $this->expectException(WebAuthnException::class);
        $this->expectExceptionMessageRegExp('~not supported~i');

        $cert->verifySignature('testmessage', hex2bin($this->getData('ecSignedData')), 7799999);
    }

    public function testWrongSignatureType()
    {
        $pem = $this->getData('v1Certificate');
        $cert = CertificateDetails::fromPEM($pem);

        $this->expectException(WebAuthnException::class);
        $this->expectExceptionMessageRegExp('~failed to verify~i');

        // Signature i  s RSA, not EC.
        $cert->verifySignature('testdata', hex2bin($this->getData('v1SignedData')), COSEAlgorithm::ES256);
    }

    public function testNoOrganizationalUnit()
    {
        $pem = $this->getData('v1Certificate');
        $cert = CertificateDetails::fromPEM($pem);

        $this->expectException(ParseException::class);
        $this->expectExceptionMessageRegExp('~organizational unit~i');

        $cert->getOrganizationalUnit();
    }

    public function testExample()
    {
        $pem = $this->getData('example.com');
        $cert = CertificateDetails::fromPEM($pem);

        $this->assertSame(CertificateDetails::VERSION_3, $cert->getCertificateVersion());
        $this->assertFalse($cert->isCA());
        $this->assertNull($cert->getFidoAaguidExtensionValue());
        $this->assertSame('Technology', $cert->getOrganizationalUnit());
    }

    public function testPacked()
    {
        $pem = $this->getData('packedAttestation');
        $cert = CertificateDetails::fromPEM($pem);

        $this->assertSame(CertificateDetails::VERSION_3, $cert->getCertificateVersion());
        $this->assertFalse($cert->isCA());
        $this->assertSame('42383245443733433846423445354132', $cert->getFidoAaguidExtensionValue()->getHex());
        $this->assertSame('Authenticator Attestation', $cert->getOrganizationalUnit());
    }

    public function testInvalidPEM()
    {
        $this->expectException(ParseException::class);
        CertificateDetails::fromPEM('ABCDEF!!!!');
    }
}

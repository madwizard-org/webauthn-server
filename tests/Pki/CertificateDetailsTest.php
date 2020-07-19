<?php

namespace MadWizard\WebAuthn\Tests\Pki;

use MadWizard\WebAuthn\Dom\CoseAlgorithm;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Pki\CertificateDetails;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;
use PHPUnit\Framework\TestCase;
use function hex2bin;

class CertificateDetailsTest extends TestCase
{
    private function getData(string $name): string
    {
        $json = FixtureHelper::getJsonFixture('Pki/testcertificates.json');
        return $json[$name];
    }

    public function testVersion1()
    {
        $pem = $this->getData('v1Certificate');
        $cert = CertificateDetails::fromPem($pem);
        $this->assertSame(CertificateDetails::VERSION_1, $cert->getCertificateVersion());
        $this->assertNull($cert->isCA());
        $this->assertNull($cert->getFidoAaguidExtensionValue());
    }

    public function testRSASignature()
    {
        $pem = $this->getData('v1Certificate');
        $cert = CertificateDetails::fromPem($pem);
        $this->assertTrue($cert->verifySignature('testdata', hex2bin($this->getData('v1SignedData')), CoseAlgorithm::RS256));
        $this->assertFalse($cert->verifySignature('testfail', hex2bin($this->getData('v1SignedData')), CoseAlgorithm::RS256));
    }

    public function testECSignature()
    {
        $pem = $this->getData('ecCertificate');
        $cert = CertificateDetails::fromPem($pem);
        $this->assertTrue($cert->verifySignature('testmessage', hex2bin($this->getData('ecSignedData')), CoseAlgorithm::ES256));
        $this->assertFalse($cert->verifySignature('testfail', hex2bin($this->getData('ecSignedData')), CoseAlgorithm::ES256));
    }

    public function testUnsupportedAlgorithm()
    {
        $pem = $this->getData('ecCertificate');
        $cert = CertificateDetails::fromPem($pem);

        $this->expectException(WebAuthnException::class);
        $this->expectExceptionMessageMatches('~not supported~i');

        $cert->verifySignature('testmessage', hex2bin($this->getData('ecSignedData')), 7799999);
    }

    public function testWrongSignatureType()
    {
        $pem = $this->getData('v1Certificate');
        $cert = CertificateDetails::fromPem($pem);

        $this->expectException(WebAuthnException::class);
        $this->expectExceptionMessageMatches('~failed to verify~i');

        // Signature i  s RSA, not EC.
        $cert->verifySignature('testdata', hex2bin($this->getData('v1SignedData')), CoseAlgorithm::ES256);
    }

    public function testNoOrganizationalUnit()
    {
        $pem = $this->getData('v1Certificate');
        $cert = CertificateDetails::fromPem($pem);

        $this->expectException(ParseException::class);
        $this->expectExceptionMessageMatches('~organizational unit~i');

        $cert->getOrganizationalUnit();
    }

    public function testExample()
    {
        $pem = $this->getData('example.com');
        $cert = CertificateDetails::fromPem($pem);

        $this->assertSame(CertificateDetails::VERSION_3, $cert->getCertificateVersion());
        $this->assertFalse($cert->isCA());
        $this->assertNull($cert->getFidoAaguidExtensionValue());
        $this->assertSame('Technology', $cert->getOrganizationalUnit());
    }

    public function testPacked()
    {
        $pem = $this->getData('packedAttestation');
        $cert = CertificateDetails::fromPem($pem);

        $this->assertSame(CertificateDetails::VERSION_3, $cert->getCertificateVersion());
        $this->assertFalse($cert->isCA());
        $this->assertSame('42383245443733433846423445354132', $cert->getFidoAaguidExtensionValue()->getHex());
        $this->assertSame('Authenticator Attestation', $cert->getOrganizationalUnit());
    }

    public function testWrongFidoExtensionType()
    {
        $pem = $this->getData('wrongFidoExtType');
        $cert = CertificateDetails::fromPem($pem);

        $this->expectException(ParseException::class);
        $this->expectExceptionMessageMatches('~failed to parse AAGUID extension~i');
        $cert->getFidoAaguidExtensionValue();
    }

    public function testFidoExtensionNonCritical()
    {
        $pem = $this->getData('fidoCritical');
        $cert = CertificateDetails::fromPem($pem);

        $this->expectException(WebAuthnException::class);
        $this->expectExceptionMessageMatches('~must not be critical~i');
        $cert->getFidoAaguidExtensionValue();
    }

    public function testInvalidPEM()
    {
        $this->expectException(ParseException::class);
        CertificateDetails::fromPem('ABCDEF!!!!');
    }
}

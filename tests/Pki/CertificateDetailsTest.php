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
        self::assertSame(CertificateDetails::VERSION_1, $cert->getCertificateVersion());
        self::assertNull($cert->isCA());
    }

    public function testRSASignature()
    {
        $pem = $this->getData('v1Certificate');
        $cert = CertificateDetails::fromPem($pem);
        self::assertTrue($cert->verifySignature('testdata', hex2bin($this->getData('v1SignedData')), CoseAlgorithm::RS256));
        self::assertFalse($cert->verifySignature('testfail', hex2bin($this->getData('v1SignedData')), CoseAlgorithm::RS256));
    }

    public function testECSignature()
    {
        $pem = $this->getData('ecCertificate');
        $cert = CertificateDetails::fromPem($pem);
        self::assertTrue($cert->verifySignature('testmessage', hex2bin($this->getData('ecSignedData')), CoseAlgorithm::ES256));
        self::assertFalse($cert->verifySignature('testfail', hex2bin($this->getData('ecSignedData')), CoseAlgorithm::ES256));
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

        self::assertSame(CertificateDetails::VERSION_3, $cert->getCertificateVersion());
        self::assertFalse($cert->isCA());
        self::assertSame('Technology', $cert->getOrganizationalUnit());
    }

    public function testPacked()
    {
        $pem = $this->getData('packedAttestation');
        $cert = CertificateDetails::fromPem($pem);

        self::assertSame(CertificateDetails::VERSION_3, $cert->getCertificateVersion());
        self::assertFalse($cert->isCA());
        self::assertSame('Authenticator Attestation', $cert->getOrganizationalUnit());
    }

    public function testInvalidPEM()
    {
        $this->expectException(ParseException::class);
        CertificateDetails::fromPem('ABCDEF!!!!');
    }
}

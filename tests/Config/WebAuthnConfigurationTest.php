<?php

namespace MadWizard\WebAuthn\Tests\Config;

use MadWizard\WebAuthn\Attestation\Registry\AttestationFormatInterface;
use MadWizard\WebAuthn\Config\WebAuthnConfiguration;
use MadWizard\WebAuthn\Dom\CoseAlgorithm;
use MadWizard\WebAuthn\Exception\ConfigurationException;
use PHPUnit\Framework\TestCase;

class WebAuthnConfigurationTest extends TestCase
{
    public function testRelyingPartyId()
    {
        $config = new WebAuthnConfiguration();
        $this->assertNull($config->getRelyingPartyId());
        $config->setRelyingPartyId('example.com');
        $this->assertSame('example.com', $config->getRelyingPartyId());
        $this->assertSame('example.com', $config->getEffectiveRelyingPartyId());
    }

    public function testNoEffectiveRelyingPartyId()
    {
        $this->expectException(ConfigurationException::class);
        $config = new WebAuthnConfiguration();
        $config->getEffectiveRelyingPartyId();
    }

    public function testRelyingPartyOrigin()
    {
        $config = new WebAuthnConfiguration();
        $config->setRelyingPartyOrigin('https://www.example.com');
        $this->assertSame('www.example.com', $config->getRelyingPartyOrigin()->getHost());
        $config->setRelyingPartyOrigin(null);
        $this->assertNull($config->getRelyingPartyOrigin());
    }

    public function testInvalidEffectiveRelyingPartyId()
    {
        $this->expectException(ConfigurationException::class);
        $config = new WebAuthnConfiguration();
        $config->setRelyingPartyId('not a domain');
    }

    public function testEffectiveRelyingPartyId()
    {
        $config = new WebAuthnConfiguration();
        $config->setRelyingPartyOrigin('https://www.example.com');
        $config->getEffectiveRelyingPartyId();
        $this->assertSame('www.example.com', $config->getEffectiveRelyingPartyId());
        $config->setRelyingPartyId('test.example');
        $this->assertSame('test.example', $config->getEffectiveRelyingPartyId());
        $config->setRelyingPartyId(null);
        $this->assertNull($config->getRelyingPartyId());
        $this->assertSame('www.example.com', $config->getEffectiveRelyingPartyId());
    }

    public function testFailGetRelyingPartyEntity()
    {
        $this->expectException(ConfigurationException::class);
        $config = new WebAuthnConfiguration();
        $config->getRelyingPartyEntity();
    }

    public function testInvalidRelyingPartyOrigin()
    {
        $this->expectException(ConfigurationException::class);
        $config = new WebAuthnConfiguration();
        $config->setRelyingPartyOrigin('not valid');
    }

    public function testRelyingPartyEntity()
    {
        $config = new WebAuthnConfiguration();

        $config->setRelyingPartyName('Relying party');

        $rpEntity = $config->getRelyingPartyEntity();
        $this->assertNull($rpEntity->getId());
        $this->assertSame('Relying party', $rpEntity->getName());

        $config->setRelyingPartyOrigin('http://www.example.com');

        // Only explicit rpID not rpID from origin should be set in entity
        $rpEntity = $config->getRelyingPartyEntity();
        $this->assertNull($rpEntity->getId());
        $this->assertSame('Relying party', $rpEntity->getName());

        $config->setRelyingPartyId('example.com');

        $rpEntity = $config->getRelyingPartyEntity();
        $this->assertSame('example.com', $rpEntity->getId());
        $this->assertSame('Relying party', $rpEntity->getName());
    }

    public function testChallengeLength()
    {
        $config = new WebAuthnConfiguration();
        $this->assertSame(WebAuthnConfiguration::DEFAULT_CHALLENGE_LENGTH, $config->getChallengeLength());

        $config->setChallengeLength(128);
        $this->assertSame(128, $config->getChallengeLength());
    }

    public function testShortChallenge()
    {
        $this->expectException(ConfigurationException::class);
        $config = new WebAuthnConfiguration();
        $config->setChallengeLength(2);
    }

    public function testDefaultAlgorithms()
    {
        $config = new WebAuthnConfiguration();
        $default = $config->getAllowedAlgorithms();
        $this->assertContains(CoseAlgorithm::ES256, $default);
        $this->assertContains(CoseAlgorithm::RS256, $default);
    }

    public function testDefaultFormats()
    {
        $config = new WebAuthnConfiguration();
        $formats = $config->getAttestationFormats();
        $formatIds = array_map(
            function (AttestationFormatInterface $f) {
                return $f->getFormatId();
            },
            $formats
        );

        $this->assertContains('none', $formatIds);
        $this->assertContains('fido-u2f', $formatIds);
    }

    public function testSetAlgorithms()
    {
        $config = new WebAuthnConfiguration();
        $algorithms = [CoseAlgorithm::ES256];
        $config->setAllowedAlgorithms($algorithms);
        $this->assertSame($algorithms, $config->getAllowedAlgorithms());
    }

    public function testInvalidAlgorithms()
    {
        $this->expectException(ConfigurationException::class);
        $config = new WebAuthnConfiguration();
        $algorithms = [1122334455];
        $config->setAllowedAlgorithms($algorithms);
    }

    public function testInvalidAlgorithmType()
    {
        $this->expectException(ConfigurationException::class);
        $config = new WebAuthnConfiguration();
        $algorithms = [CoseAlgorithm::ES256, 'not valid'];
        $config->setAllowedAlgorithms($algorithms);
    }
}

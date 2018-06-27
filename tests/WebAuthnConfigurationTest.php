<?php

namespace MadWizard\WebAuthn\Tests;

use MadWizard\WebAuthn\Config\WebAuthnConfiguration;
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
        $this->assertSame('example.com', $config->getEffectiveReyingPartyId());
    }

    public function testNoEffectiveReyingPartyId()
    {
        $this->expectException(ConfigurationException::class);
        $config = new WebAuthnConfiguration();
        $config->getEffectiveReyingPartyId();
    }

    /*
        public function testInvalidEffectiveReyingPartyId()
        {
            $this->expectException(ConfigurationException::class);
            $config = new WebAuthnConfiguration();
            $config->setRelyingPartyId('not a domain');
        }
    */
    public function testEffectiveReyingPartyId()
    {
        $config = new WebAuthnConfiguration();
        $config->setRelyingPartyOrigin('https://www.example.com');
        $config->getEffectiveReyingPartyId();
        $this->assertSame('www.example.com', $config->getEffectiveReyingPartyId());
        $config->setRelyingPartyId('test.example');
        $this->assertSame('test.example', $config->getEffectiveReyingPartyId());
        $config->setRelyingPartyId(null);
        $this->assertNull($config->getRelyingPartyId());
        $this->assertSame('www.example.com', $config->getEffectiveReyingPartyId());
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
}

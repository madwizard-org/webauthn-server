<?php


namespace MadWizard\WebAuthn\Tests\Config;

use MadWizard\WebAuthn\Config\RelyingParty;
use MadWizard\WebAuthn\Exception\ConfigurationException;
use PHPUnit\Framework\TestCase;

class RelyingPartyTest extends TestCase
{
    public function testRelyingPartyEntity()
    {
        $rp = new RelyingParty('Relying party', 'https://localhost');

        $this->assertSame('Relying party', $rp->getName());
        $this->assertSame('https://localhost', $rp->getOrigin()->toString());
        $this->assertNull($rp->getId());
        $this->assertSame('localhost', $rp->getEffectiveId());
        $this->assertNull($rp->getIconUrl());

        $rp->setOrigin('https://www.example.com');

        $this->assertNull($rp->getId());
        $this->assertSame('www.example.com', $rp->getEffectiveId());
        $this->assertSame('https://www.example.com', $rp->getOrigin()->toString());
        $this->assertNull($rp->getIconUrl());


        $imgUrl = 'data:image/png;base64,YWJj';
        $rp->setIconUrl($imgUrl);
        $this->assertSame($imgUrl, $rp->getIconUrl());
    }

    public function testRelyingPartyId()
    {
        $rp = new RelyingParty('Example', 'https://example.com');
        $this->assertNull($rp->getId());
        $rp->setId('example.com');
        $this->assertSame('example.com', $rp->getId());
        $this->assertSame('example.com', $rp->getEffectiveId());
    }

    public function testRelyingPartyOrigin()
    {
        $rp = new RelyingParty('Example', 'https://www.example.com');
        $this->assertSame('www.example.com', $rp->getOrigin()->getHost());
    }

    public function testInvalidEffectiveRelyingPartyId()
    {
        $this->expectException(ConfigurationException::class);
        $rp = new RelyingParty('Example', 'https://example.com');
        $rp->setId('not a domain');
    }

    public function testEffectiveRelyingPartyId()
    {
        $rp = new RelyingParty('Example', 'https://www.example.com');
        $this->assertSame('www.example.com', $rp->getEffectiveId());
        $rp->setId('test.example');
        $this->assertSame('test.example', $rp->getEffectiveId());
        $rp->setId(null);
        $this->assertNull($rp->getId());
        $this->assertSame('www.example.com', $rp->getEffectiveId());
    }

    public function testInvalidRelyingPartyOrigin()
    {
        $this->expectException(ConfigurationException::class);
        $rp = new RelyingParty('Example', 'https://www.example.com');
        $rp->setOrigin('not valid');
    }
}

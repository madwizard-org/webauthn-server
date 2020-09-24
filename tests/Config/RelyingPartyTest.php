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

        self::assertSame('Relying party', $rp->getName());
        self::assertSame('https://localhost', $rp->getOrigin()->toString());
        self::assertNull($rp->getId());
        self::assertSame('localhost', $rp->getEffectiveId());
        self::assertNull($rp->getIconUrl());

        $rp->setOrigin('https://www.example.com');

        self::assertNull($rp->getId());
        self::assertSame('www.example.com', $rp->getEffectiveId());
        self::assertSame('https://www.example.com', $rp->getOrigin()->toString());
        self::assertNull($rp->getIconUrl());

        $imgUrl = 'data:image/png;base64,YWJj';
        $rp->setIconUrl($imgUrl);
        self::assertSame($imgUrl, $rp->getIconUrl());
    }

    public function testRelyingPartyId()
    {
        $rp = new RelyingParty('Example', 'https://example.com');
        self::assertNull($rp->getId());
        $rp->setId('example.com');
        self::assertSame('example.com', $rp->getId());
        self::assertSame('example.com', $rp->getEffectiveId());
    }

    public function testRelyingPartyOrigin()
    {
        $rp = new RelyingParty('Example', 'https://www.example.com');
        self::assertSame('www.example.com', $rp->getOrigin()->getHost());
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
        self::assertSame('www.example.com', $rp->getEffectiveId());
        $rp->setId('test.example');
        self::assertSame('test.example', $rp->getEffectiveId());
        $rp->setId(null);
        self::assertNull($rp->getId());
        self::assertSame('www.example.com', $rp->getEffectiveId());
    }

    public function testInvalidRelyingPartyOrigin()
    {
        $this->expectException(ConfigurationException::class);
        $rp = new RelyingParty('Example', 'https://www.example.com');
        $rp->setOrigin('not valid');
    }
}

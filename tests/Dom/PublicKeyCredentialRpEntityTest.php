<?php

namespace MadWizard\WebAuthn\Tests\Dom;

use MadWizard\WebAuthn\Config\RelyingParty;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialRpEntity;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use PHPUnit\Framework\TestCase;

class PublicKeyCredentialRpEntityTest extends TestCase
{
    public function testFromObjectMinimal()
    {
        $rp = new RelyingParty('Relying party', 'http://localhost');
        $rpEntity = PublicKeyCredentialRpEntity::fromRelyingParty($rp);
        $this->assertNull($rpEntity->getIcon());
        $this->assertNull($rpEntity->getId());
        $this->assertSame('Relying party', $rpEntity->getName());
        $this->assertSame([
                'name' => 'Relying party',
        ], $rpEntity->getAsArray());
    }

    public function testFromObjectFull()
    {
        $rp = new RelyingParty('Relying party', 'http://localhost');
        $imgUrl = 'data:image/png;base64,YWJj';
        $rp->setIconUrl($imgUrl);
        $rp->setId('localhost');

        $rpEntity = PublicKeyCredentialRpEntity::fromRelyingParty($rp);
        $this->assertSame($imgUrl, $rpEntity->getIcon());
        $this->assertSame('localhost', $rpEntity->getId());
        $this->assertSame('Relying party', $rpEntity->getName());
        $this->assertSame([
            'name' => 'Relying party',
            'icon' => $imgUrl,
            'id' => 'localhost',
        ], $rpEntity->getAsArray());
    }

    public function testCreateMinimal()
    {
        $rpEntity = new PublicKeyCredentialRpEntity('Testing');
        $this->assertNull($rpEntity->getId());
        $this->assertNull($rpEntity->getIcon());
        $this->assertSame('Testing', $rpEntity->getName());
        $this->assertSame([
            'name' => 'Testing',
        ], $rpEntity->getAsArray());
    }

    public function testCreateFull()
    {
        $imgUrl = 'data:image/png;base64,YWJj';
        $rpEntity = new PublicKeyCredentialRpEntity('Relying party', 'localhost');
        $rpEntity->setIcon($imgUrl);
        $this->assertSame($imgUrl, $rpEntity->getIcon());
        $this->assertSame('localhost', $rpEntity->getId());
        $this->assertSame('Relying party', $rpEntity->getName());
        $this->assertSame([
            'name' => 'Relying party',
            'icon' => $imgUrl,
            'id' => 'localhost',
        ], $rpEntity->getAsArray());
    }

    public function testCreateInvalidDomain()
    {
        $this->expectException(WebAuthnException::class);
        new PublicKeyCredentialRpEntity('Testing', 'not valid');
    }
}

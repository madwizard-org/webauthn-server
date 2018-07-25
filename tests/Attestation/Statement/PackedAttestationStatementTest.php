<?php


namespace MadWizard\WebAuthn\Tests\Attestation\Statement;

use MadWizard\WebAuthn\Attestation\Statement\FidoU2fAttestationStatement;
use MadWizard\WebAuthn\Attestation\Statement\PackedAttestationStatement;
use MadWizard\WebAuthn\Dom\COSEAlgorithm;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;
use PHPUnit\Framework\TestCase;

class PackedAttestationStatementTest extends TestCase
{
    public function testFidoU2f()
    {
        $attObj = FixtureHelper::getFidoTestObject('challengeResponseAttestationPackedB64UrlMsg');
        $chains = FixtureHelper::getFidoTestPlain('certChains');

        $statement = new PackedAttestationStatement($attObj);

        $this->assertSame('packed', $statement->getFormatId());

        $this->assertNull($statement->getEcdaaKeyId());
        $certChain = $statement->getCertificates();

        $this->assertSame($chains['packed'], $certChain);

        $this->assertSame(
            '30460221008b0ad16afdb66b9dfb0688628430db45168bb0cbfe00f1fcf346dcf079ede1' .
            'cb022100b51c9dfb8248da90955fe743cf899b1dcfc092f0b777fe2a9c105ade7d88fe15',
            $statement->getSignature()->getHex()
        );

        $this->assertSame(COSEAlgorithm::ES256, $statement->getAlgorithm());
    }

    public function testEcdaaKey()
    {
        $attObj = FixtureHelper::getFidoTestObject('dummyPackedEcdaaKeyStatment');


        $statement = new PackedAttestationStatement($attObj);

        $this->assertSame('packed', $statement->getFormatId());
        $this->assertSame('aabbccdd', $statement->getEcdaaKeyId()->getHex());
        $this->assertNull($statement->getCertificates());
    }

    public function testNoKeyNoX5C()
    {
        $attObj = FixtureHelper::getFidoTestObject('dummyPackedNoKeyNoX5C');

        $statement = new PackedAttestationStatement($attObj);
        $this->assertNull($statement->getEcdaaKeyId());
        $this->assertNull($statement->getCertificates());
    }

    public function testBothKeyAndX5C()
    {
        $attObj = FixtureHelper::getFidoTestObject('dummyPackedBothKeyAndX5C');

        $this->expectException(ParseException::class);
        $this->expectExceptionMessageRegExp('~ecdaaKeyId and x5c cannot both be set~i');

        new PackedAttestationStatement($attObj);
    }

    public function testWrongFormat()
    {
        $this->expectException(ParseException::class);
        $this->expectExceptionMessageRegExp('~not expecting format~i');

        $attObj = FixtureHelper::getTestObject('none');

        new FidoU2fAttestationStatement($attObj);
    }

    public function testInvalidStatementMap()
    {
        $attObj = FixtureHelper::getFidoTestObject('invalidPackedStatementMap');
        $this->expectException(ParseException::class);
        $this->expectExceptionMessageRegExp('~invalid .+ attestation statement~i');
        new PackedAttestationStatement($attObj);
    }

    public function testCreateFormat()
    {
        $format = PackedAttestationStatement::createFormat();
        $this->assertSame(PackedAttestationStatement::FORMAT_ID, $format->getFormatId());
    }
}

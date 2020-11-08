<?php

namespace MadWizard\WebAuthn\Tests\Attestation\Statement;

use MadWizard\WebAuthn\Attestation\Statement\PackedAttestationStatement;
use MadWizard\WebAuthn\Crypto\CoseAlgorithm;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Tests\Helper\CertHelper;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;
use PHPUnit\Framework\TestCase;

class PackedAttestationStatementTest extends TestCase
{
    public function testFidoU2f()
    {
        $attObj = FixtureHelper::getFidoTestObject('challengeResponseAttestationPackedB64UrlMsg');
        $chains = FixtureHelper::getFidoTestPlain('certChains');

        $statement = new PackedAttestationStatement($attObj);

        self::assertSame('packed', $statement->getFormatId());

        self::assertNull($statement->getEcdaaKeyId());
        $certChain = $statement->getCertificates();

        self::assertSame($chains['packed'], CertHelper::pemList(...$certChain));

        self::assertSame(
            '30460221008b0ad16afdb66b9dfb0688628430db45168bb0cbfe00f1fcf346dcf079ede1' .
            'cb022100b51c9dfb8248da90955fe743cf899b1dcfc092f0b777fe2a9c105ade7d88fe15',
            $statement->getSignature()->getHex()
        );

        self::assertSame(CoseAlgorithm::ES256, $statement->getAlgorithm());
    }

    public function testEcdaaKey()
    {
        $attObj = FixtureHelper::getFidoTestObject('dummyPackedEcdaaKeyStatment');

        $statement = new PackedAttestationStatement($attObj);

        self::assertSame('packed', $statement->getFormatId());
        self::assertSame('aabbccdd', $statement->getEcdaaKeyId()->getHex());
        self::assertNull($statement->getCertificates());
    }

    public function testNoKeyNoX5C()
    {
        $attObj = FixtureHelper::getFidoTestObject('dummyPackedNoKeyNoX5C');

        $statement = new PackedAttestationStatement($attObj);
        self::assertNull($statement->getEcdaaKeyId());
        self::assertNull($statement->getCertificates());
    }

    public function testBothKeyAndX5C()
    {
        $attObj = FixtureHelper::getFidoTestObject('dummyPackedBothKeyAndX5C');

        $this->expectException(ParseException::class);
        $this->expectExceptionMessageMatches('~ecdaaKeyId and x5c cannot both be set~i');

        new PackedAttestationStatement($attObj);
    }

    public function testInvalidStatementMap()
    {
        $attObj = FixtureHelper::getFidoTestObject('invalidPackedStatementMap');
        $this->expectException(ParseException::class);
        $this->expectExceptionMessageMatches('~invalid .+ attestation statement~i');
        new PackedAttestationStatement($attObj);
    }
}

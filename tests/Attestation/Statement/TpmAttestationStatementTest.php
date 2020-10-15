<?php

namespace MadWizard\WebAuthn\Tests\Attestation\Statement;

use MadWizard\WebAuthn\Attestation\Statement\TpmAttestationStatement;
use MadWizard\WebAuthn\Attestation\Tpm\TpmPublic;
use MadWizard\WebAuthn\Crypto\CoseAlgorithm;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;
use MadWizard\WebAuthn\Tests\Helper\HexData;
use PHPUnit\Framework\TestCase;

class TpmAttestationStatementTest extends TestCase
{
    private const RAW_CERTINFO =
        'ff54434780170022000bbc59f4dfd9a6a42dc3b866aff2df0d19826bbf014b67
         ab0ad6ebb176306b80070014ac9f3f0569c662fb091491f1eee318c6f0c3df9b
         00000001b15a48c76840f9e3d8f39f0501a9e0c4a53fbbc4130022000b7121ae
         bfa6b9afd07032f42f0925e0ec67408dd599a57bfa0f80c7f15601084f002200
         0b015234790fc00198cdbeb85410c2b6ab8c31bb02053a71c80c5d1096385fe3
         b4';

    private const RAW_SIG =
        '715d62cd6194588b340c439935019dae234d5e8ea76eb1832f31007acc022bd9
         e360608b98e9075604b269f86c8c210c664426b8f52610e3032a8b2ac6ea7fb6
         25d0c06e32096f53c96a0835619ac90e2f72be98b3e97a28c3e483ffddd95cb0
         85fa279d324305f13fe012110fad06474a81cd36abb610c740532a46da14b6e3
         ac4c5e6379d5371103e88d1039882342da7682099b8c49445d94f9a1956e6b01
         a459545e356591028b988538cdab3b45291ae4122d4bebd4ca903ac0f2b4c7fb
         a9664cbf04ffe7ff0117a18d741da5d95ce620905b57a83ccfb763d1f4648e50
         97069f141b62ef4eae52b1fba0ad1597389f0191d32994f7e5d26cfab2c53f9f
        ';

    public function testTpm()
    {
        $attObj = FixtureHelper::getFidoTestObject('challengeResponseAttestationTpmB64UrlMsg');
        $chains = FixtureHelper::getFidoTestPlain('certChains');

        $statement = new TpmAttestationStatement($attObj);

        self::assertSame('tpm', $statement->getFormatId());
        self::assertSame(CoseAlgorithm::RS1, $statement->getAlgorithm());
        self::assertSame(HexData::hex(self::RAW_CERTINFO), $statement->getRawCertInfo()->getHex());
        self::assertSame(HexData::hex(self::RAW_SIG), $statement->getSignature()->getHex());
        self::assertNull($statement->getEcdaaKeyId());
        self::assertSame($chains['tpm'], $statement->getCertificates());
        self::assertSame(TpmPublic::TPM_ALG_RSA, $statement->getPubArea()->getType());
        self::assertSame('000b7121aebfa6b9afd07032f42f0925e0ec67408dd599a57bfa0f80c7f15601084f', $statement->getCertInfo()->getAttName()->getHex());
    }

    public function testMissingFields()
    {
        $attObj = FixtureHelper::getFidoTestObject('missingFieldsTpmAttestation');

        $this->expectException(ParseException::class);
        $this->expectExceptionMessageMatches('~invalid TPM~i');
        new TpmAttestationStatement($attObj);
    }

    public function testBothKeyAndX5C()
    {
        $attObj = FixtureHelper::getFidoTestObject('bothKeyAndX5CTpmAttestation');

        $this->expectException(ParseException::class);
        $this->expectExceptionMessageMatches('~ecdaaKeyId and x5c cannot both~i');
        new TpmAttestationStatement($attObj);
    }
}

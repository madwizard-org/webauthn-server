<?php


namespace MadWizard\WebAuthn\Tests\Attestation;

use MadWizard\WebAuthn\Attestation\AuthenticatorData;
use MadWizard\WebAuthn\Crypto\Ec2Key;
use MadWizard\WebAuthn\Dom\CoseAlgorithm;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Tests\Helper\HexData;
use PHPUnit\Framework\TestCase;

class AuthenticatorDataTest extends TestCase
{
    public function testParseExample()
    {
        // Example data from FIDO2 spec
        $buf = HexData::buf(
            '1194228DA8FDBDEEFD261BD7B6595CFD70A50D70C6407BCF013DE96D4EFB17DE    # rpidhash
            41                                                                  # flags
            00000000                                                            # Sign Count
            00000000000000000000000000000000                                    # AAGUID
            0040                                                                # Key Handle Length (1 Byte)
            3EBD89BF77EC509755EE9C2635EFAAAC7B2B9C5CEF1736C3717DA48534C8C6B6    # Key Handle (Key Handle Length Bytes)
            54D7FF945F50B5CC4E78055BDD396B64F78DA2C5F96200CCD415CD08FE420038    # ...
            A5010203262001215820E87625896EE4E46DC032766E8087962F36DF9DFE8B56    # Public Key
            7F3763015B1990A60E1422582027DE612D66418BDA1950581EBC5C8C1DAD710C    # ...
            B14C22F8C97045F4612FB20C91                                          # ...
            '
        );


        $data = new AuthenticatorData($buf);

        $this->assertSame('1194228da8fdbdeefd261bd7b6595cfd70a50d70c6407bcf013de96d4efb17de', $data->getRpIdHash()->getHex());
        $this->assertTrue($data->isUserPresent());
        $this->assertFalse($data->isUserVerified());
        $this->assertTrue($data->hasAttestedCredentialData());
        $this->assertFalse($data->hasExtensionData());
        $this->assertSame(0, $data->getSignCount());
        $this->assertTrue($data->getCredentialId()->equals(ByteBuffer::fromHex('3ebd89bf77ec509755ee9c2635efaaac7b2b9c5cef1736c3717da48534c8c6b654d7ff945f50b5cc4e78055bdd396b64f78da2c5f96200ccd415cd08fe420038')));

        $this->assertTrue($data->hasKey());
        $key = $data->getKey();
        $this->assertInstanceOf(Ec2Key::class, $key);
        /**
         * @var Ec2Key $key
         */
        $this->assertEquals(CoseAlgorithm::ES256, $key->getAlgorithm());
        $this->assertEquals(Ec2Key::CURVE_P256, $key->getCurve());
        $this->assertSame('e87625896ee4e46dc032766e8087962f36df9dfe8b567f3763015b1990a60e14', $key->getX()->getHex());
        $this->assertSame('27de612d66418bda1950581ebc5c8c1dad710cb14c22f8c97045f4612fb20c91', $key->getY()->getHex());
    }
}

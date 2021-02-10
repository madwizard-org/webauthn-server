<?php

namespace MadWizard\WebAuthn\Tests\Crypto;

use MadWizard\WebAuthn\Crypto\CoseAlgorithm;
use MadWizard\WebAuthn\Crypto\CoseKey;
use MadWizard\WebAuthn\Crypto\OkpKey;
use MadWizard\WebAuthn\Exception\VerificationException;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Format\CborMap;
use MadWizard\WebAuthn\Tests\Helper\HexData;
use PHPUnit\Framework\TestCase;

class OkpKeyTest extends TestCase
{
    private const TEST_KEY_X = '081b32aa6e5fc0dc33d7f3afe83be5412b0ea7d3b304656269e2655dcec90c17';

    public function testSignature()
    {
        $signature = HexData::buf(
            'B7D680DC91D3FBAB3D0382F22E96640F9B5D01F6E0E5457503DD802987FD87F0807447C18D3786A8C1C2754ED7A60CAE105DBA7FD2103BD51654534DD10BA804'
        );

        $wrongSignature = HexData::buf(
            'B7D680DC91D3FBAB3D0382F22E96640F9B5D01F6E0E5457503DD802787FD87F0807447C18D3786A8C1C2754ED7A60CAE105DBA7FD2103BD51654534DD10BA804' // changed one digit
        );

        $differentMessageSignature = HexData::buf(
            '8CDF432EAEE68B35EBDCC4FADD11D05BC8C1D01A6EDD36C9398E7C61AF1D994801B6B27F4E0AC1C21912AB09AE7EE6AA40721C835818C16B8DE9060F8F3A4A0B'
        );
        $message = new ByteBuffer('testmessage');

        $key = $this->getKey();

        $valid = $key->verifySignature($message, $signature);
        self::assertTrue($valid);

        $valid = $key->verifySignature($message, $wrongSignature);
        self::assertFalse($valid);

        $valid = $key->verifySignature(new ByteBuffer('diffmessage'), $wrongSignature);
        self::assertFalse($valid);

        $valid = $key->verifySignature($message, $differentMessageSignature);
        self::assertFalse($valid);
    }

    public function testInvalidData()
    {
        $signature = HexData::buf('112233');

        $message = new ByteBuffer('testmessage');

        $key = $this->getKey();

        $this->expectException(VerificationException::class);
        $key->verifySignature($message, $signature);
    }

    public function testPEM()
    {
        $pem = $this->getKey()->asPem();

        self::assertSame(
            "-----BEGIN PUBLIC KEY-----\n" .
            "MCowBQYDK2VwAyEACBsyqm5fwNwz1/Ov6DvlQSsOp9OzBGViaeJlXc7JDBc=\n" .
            "-----END PUBLIC KEY-----\n",
            $pem
        );
    }

    public function testProperties()
    {
        $key = $this->getKey();

        self::assertSame(self::TEST_KEY_X, $key->getX()->getHex());
        self::assertSame(OkpKey::CURVE_ED25519, $key->getCurve());
        self::assertSame(CoseAlgorithm::EDDSA, $key->getAlgorithm());
    }

    public function testInvalidCbor()
    {
        $this->expectException(WebAuthnException::class);
        OkpKey::fromCborData(new CborMap());
    }

    public function testInvalidType()
    {
        $this->expectException(WebAuthnException::class);
        OkpKey::fromCborData(CborMap::fromArray([-1 => 'a', -2 => 1, -3 => 2]));
    }

    public function testCbor()
    {
        $cbor = HexData::buf(
            'A4
             01  01  #   1:   1,  ; kty: OKP key type
             03  27  #   3:  -8,  ; alg: EDDSA signature algorithm
             20  06  #  -1:   6,  ; crv: Ed25519 curve
             21  58 20  081b32aa6e5fc0dc33d7f3afe83be5412b0ea7d3b304656269e2655dcec90c17 # -2:   x,  ; x-coordinate'
        );

        $key = CoseKey::parseCbor($cbor);
        self::assertInstanceOf(OkpKey::class, $key);

        /* @var OkpKey $key */
        self::assertSame(self::TEST_KEY_X, $key->getX()->getHex());
        self::assertSame(OkpKey::CURVE_ED25519, $key->getCurve());
        self::assertSame(CoseAlgorithm::EDDSA, $key->getAlgorithm());
        self::assertSame('081b32aa6e5fc0dc33d7f3afe83be5412b0ea7d3b304656269e2655dcec90c17', $key->getX()->getHex());

        // Transform back
        $output = $key->getCbor();

        self::assertSame($cbor->getHex(), $output->getHex());
    }

    private function getKey(): OkpKey
    {
        $x = ByteBuffer::fromHex(self::TEST_KEY_X);
        return new OkpKey($x, OkpKey::CURVE_ED25519, CoseAlgorithm::EDDSA);
    }
}

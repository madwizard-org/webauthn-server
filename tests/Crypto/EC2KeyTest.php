<?php

namespace MadWizard\WebAuthn\Tests\Crypto;

use MadWizard\WebAuthn\Crypto\COSEKey;
use MadWizard\WebAuthn\Crypto\EC2Key;
use MadWizard\WebAuthn\Dom\COSEAlgorithm;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Tests\Helper\HexData;
use PHPUnit\Framework\TestCase;

class EC2KeyTest extends TestCase
{
    private const TEST_KEY_X = '3c7035f8fa4b22c97092e166a7021ee1c5e4a83c2875883a110fc29ef66a6a0d';

    private const TEST_KEY_Y = 'f041a1d4395a069149fc7cfddd7e0bc5c77411b62f46bbbf1f7d1fc5174fd490';

    public function testSignature()
    {
        $signature = HexData::buf(
            '3045022100ED20111EC9FFB3A88259980A21FFD25417AA27DCC9CC7F27B443B9
            EE49A58FB802205AF6ABAD0AA3421F0BF4155809B240EDCBE525924FFBB94F9DE
            FEDE785572961'
        );

        $wrongSignature = HexData::buf(
            '3045022100ED20111EC9FFB3A88259980A21FFD25417AA27DCC9CC7F27B443B8 # Last digit changed to 8
            EE49A58FB802205AF6ABAD0AA3421F0BF4155809B240EDCBE525924FFBB94F9DE
            FEDE785572961'
        );
        $message = new ByteBuffer('testmessage');

        $key = $this->getKey();

        $valid = $key->verifySignature($message, $signature);
        $this->assertTrue($valid);


        $valid = $key->verifySignature($message, $wrongSignature);
        $this->assertFalse($valid);
    }

    public function testInvalidData()
    {
        $signature = HexData::buf('112233');

        $message = new ByteBuffer('testmessage');

        $key = $this->getKey();

        $this->expectException(WebAuthnException::class);
        $key->verifySignature($message, $signature);
    }

    public function testPEM()
    {
        $pem = $this->getKey()->asPEM();

        $this->assertSame(
            "-----BEGIN PUBLIC KEY-----\n" .
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPHA1+PpLIslwkuFmpwIe4cXkqDwo\n" .
            "dYg6EQ/CnvZqag3wQaHUOVoGkUn8fP3dfgvFx3QRti9Gu78ffR/FF0/UkA==\n" .
            "-----END PUBLIC KEY-----\n",
            $pem
        );
    }

    public function testProperties()
    {
        $key = $this->getKey();

        $this->assertSame(self::TEST_KEY_X, $key->getX()->getHex());
        $this->assertSame(self::TEST_KEY_Y, $key->getY()->getHex());
        $this->assertSame(EC2Key::CURVE_P256, $key->getCurve());
        $this->assertSame(COSEAlgorithm::ES256, $key->getAlgorithm());
    }

    public function testInvalidCBOR()
    {
        $this->expectException(WebAuthnException::class);
        EC2Key::fromCBORData([]);
    }

    public function testInvalidType()
    {
        $this->expectException(WebAuthnException::class);
        EC2Key::fromCBORData([-1 => 'a', -2 => 1, -3 => 2]);
    }

    public function testCBOR()
    {
        // Example key from webauthn spec
        $cbor = HexData::buf(
            'A5        
             01  02  #   1:   2,  ; kty: EC2 key type
             03  26  #   3:  -7,  ; alg: ES256 signature algorithm
             20  01  #  -1:   1,  ; crv: P-256 curve
             21  58 20   65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d # -2:   x,  ; x-coordinate
             22  58 20   1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c # -3:   y,  ; y-coordinate'
        );

        $key = COSEKey::parseCBOR($cbor);
        $this->assertInstanceOf(EC2Key::class, $key);
        /** @var $key EC2Key */

        $this->assertSame(EC2Key::CURVE_P256, $key->getCurve());
        $this->assertSame(COSEAlgorithm::ES256, $key->getAlgorithm());
        $this->assertSame('65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d', $key->getX()->getHex());
        $this->assertSame('1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c', $key->getY()->getHex());

        // Transform back
        $output = $key->getCBOR();

        $this->assertSame($cbor->getHex(), $output->getHex());
    }

    private function getKey(): EC2Key
    {
        $x = ByteBuffer::fromHex(self::TEST_KEY_X);
        $y = ByteBuffer::fromHex(self::TEST_KEY_Y);
        return new EC2Key($x, $y, EC2Key::CURVE_P256, COSEAlgorithm::ES256);
    }
}

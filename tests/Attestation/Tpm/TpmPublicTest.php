<?php


namespace MadWizard\WebAuthn\Tests\Attestation\Tpm;

use MadWizard\WebAuthn\Attestation\Tpm\TpmPublic;
use MadWizard\WebAuthn\Attestation\Tpm\TpmRsaParameters;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Exception\UnsupportedException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Tests\Helper\HexData;
use PHPUnit\Framework\TestCase;

class TpmPublicTest extends TestCase
{
    private const TPMT_PUBLIC_EXAMPLE =
        '0001 # type
         000b # Name alg
         00060472 # Object attributes
         0020 # Auth policy length 
         9dffcbf36c383ae699fb9868dc6dcb89d7153884be2803922c124158bfad22ae # Auth policy
         00100010080000000000 # Parameters (10 bytes RSA)
         0100 # Unique length
         c5da6f4d9357bde202f5c558cd0a3156d254f2e0ad9ab57931f9826b747de1ac # Unique (2048 bits)
         4f29d6070874dce57910e19844499d8e42470339b170d022b501ab88e9c2f4ed
         302e4719c70debe8842403ed9bdfc22730a61a1b70f616c5f1b700cacf784613
         7dc4b2d469a8e15aab4fad8657084022d28f44d9075323126b7007c981939fdf
         724caf4fbe475040431a4ea064430bcb2cfad7d05bdb9f64b5b0e0952ecf8679
         273d6c6dfa81601f14503316a13d0782c31a3e6bdded3d7bc46bc1fa9bef0dff
         83b7deaf146b582c4644821a3c62edbaa6be422bf04e43edaf5fd3783086153d
         7361a203061a6298ab26e1337ca1c9ed06741a5905477988e720304eae189d7f
         ';

    private const RSA_KEY_BITS =
        'c5da6f4d9357bde202f5c558cd0a3156d254f2e0ad9ab57931f9826b747de1ac
         4f29d6070874dce57910e19844499d8e42470339b170d022b501ab88e9c2f4ed
         302e4719c70debe8842403ed9bdfc22730a61a1b70f616c5f1b700cacf784613
         7dc4b2d469a8e15aab4fad8657084022d28f44d9075323126b7007c981939fdf
         724caf4fbe475040431a4ea064430bcb2cfad7d05bdb9f64b5b0e0952ecf8679
         273d6c6dfa81601f14503316a13d0782c31a3e6bdded3d7bc46bc1fa9bef0dff
         83b7deaf146b582c4644821a3c62edbaa6be422bf04e43edaf5fd3783086153d
         7361a203061a6298ab26e1337ca1c9ed06741a5905477988e720304eae189d7f';

    public function testParse()
    {
        $raw = HexData::buf(self::TPMT_PUBLIC_EXAMPLE);

        $public = new TpmPublic($raw);

        $this->assertSame(TpmPublic::TPM_ALG_RSA, $public->getType());
        $this->assertSame(TpmPublic::TPM_ALG_SHA256, $public->getNameAlg());
        $this->assertSame(0x00060472, $public->getObjectAttributes());
        $this->assertTrue(
            $public->isValidPubInfoName(
                ByteBuffer::fromHex('000b7121aebfa6b9afd07032f42f0925e0ec67408dd599a57bfa0f80c7f15601084f')
            )
        );

        $this->assertSame(HexData::buf(self::RSA_KEY_BITS)->getHex(), $public->getUnique()->getHex());

        $parameters = $public->getParameters();
        $this->assertInstanceOf(TpmRsaParameters::class, $parameters);

        /** @var TpmRsaParameters $parameters */
        $this->assertSame(65537, $parameters->getExponent());
        $this->assertSame(TpmPublic::TPM_ALG_NULL, $parameters->getSymmetric());
        $this->assertSame(TpmPublic::TPM_ALG_NULL, $parameters->getScheme());
        $this->assertSame(2048, $parameters->getKeyBits());
    }

    public function testExtra()
    {
        $raw = HexData::buf(self::TPMT_PUBLIC_EXAMPLE . PHP_EOL . 'aa');
        $this->expectException(ParseException::class);
        $this->expectExceptionMessageRegExp('~unexpected bytes~i');
        new TpmPublic($raw);
    }

    public function testInvalidNameAlg()
    {
        $raw = HexData::buf(self::TPMT_PUBLIC_EXAMPLE);
        $public = new TpmPublic($raw);
        $this->expectException(UnsupportedException::class);
        $this->expectExceptionMessageRegExp('~0xFAFB~i');
        $public->isValidPubInfoName(ByteBuffer::fromHex('FAFB00112233'));
    }
}

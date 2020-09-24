<?php

namespace MadWizard\WebAuthn\Tests\Attestation\Tpm;

use MadWizard\WebAuthn\Attestation\Tpm\TpmAttest;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Tests\Helper\HexData;
use PHPUnit\Framework\TestCase;

class TpmAttestTest extends TestCase
{
    private const TPMT_ATTEST_EXAMPLE =
        'ff544347 # Magic
         8017 # Type
         0022 # Qualified signer length
         000bbc59f4dfd9a6a42dc3b866aff2df0d19826bbf014b67ab0ad6ebb176306b8007 # Qualified signer
         0014 # Extra data length
         ac9f3f0569c662fb091491f1eee318c6f0c3df9b # Extra data
         00000001b15a48c76840f9e3d8f39f0501 # Clockinfo
         a9e0c4a53fbbc413 # Firmware version
         0022 # Attested name length
         000b7121aebfa6b9afd07032f42f0925e0ec67408dd599a57bfa0f80c7f15601084f # Attested name
         0022 # Attestded qualified name length
         000b015234790fc00198cdbeb85410c2b6ab8c31bb02053a71c80c5d1096385fe3b4 # Attested qualified name
         ';

    public function testParse()
    {
        $raw = HexData::buf(self::TPMT_ATTEST_EXAMPLE);
        $attest = new TpmAttest($raw);

        self::assertSame('000b7121aebfa6b9afd07032f42f0925e0ec67408dd599a57bfa0f80c7f15601084f', $attest->getAttName()->getHex());
    }

    public function testExtra()
    {
        $raw = HexData::buf(self::TPMT_ATTEST_EXAMPLE . PHP_EOL . 'aa');
        $this->expectException(ParseException::class);
        $this->expectExceptionMessageMatches('~unexpected bytes~i');
        new TpmAttest($raw);
    }

    public function testInvalidMagic()
    {
        $data = HexData::bin(self::TPMT_ATTEST_EXAMPLE);

        // Modify magic
        $data[1] = \chr(0x66);

        $raw = new ByteBuffer($data);

        $this->expectException(ParseException::class);
        $this->expectExceptionMessageMatches('~magic~i');

        new TpmAttest($raw);
    }

    public function testWrongType()
    {
        $data = HexData::bin(self::TPMT_ATTEST_EXAMPLE);

        // Modify type
        $data[5] = \chr(0x66);

        $raw = new ByteBuffer($data);

        $this->expectException(ParseException::class);
        $this->expectExceptionMessageMatches('~TPM_ST_ATTEST_CERTIFY~i');

        new TpmAttest($raw);
    }
}

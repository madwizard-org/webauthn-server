<?php


namespace MadWizard\WebAuthn\Tests\Cbor;

use const PHP_INT_SIZE;
use MadWizard\WebAuthn\Exception\CborException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Format\CborDecoder;
use MadWizard\WebAuthn\Format\CborEncoder;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;
use MadWizard\WebAuthn\Tests\Helper\HexData;
use PHPUnit\Framework\TestCase;
use function bin2hex;
use function hex2bin;
use function json_decode;
use function var_dump;

class CborTest extends TestCase
{
    private function convertByteBuffers($value)
    {
        if ($value instanceof ByteBuffer) {
            return 'HEX:' . bin2hex($value->getBinaryString());
        }
        if (!is_array($value)) {
            return $value;
        }

        return array_map([$this, 'convertByteBuffers'], $value);
    }

    public function testVectors()
    {
        $tests = json_decode(FixtureHelper::getFixtureContent('Cbor/testvectors.json'), true);

        foreach ($tests as $test) {
            $message = sprintf('Cbor hex: ' . $test['hex']);

            $buffer = ByteBuffer::fromHex($test['hex']);

            $errorMessage = null;
            try {
                $result = CborDecoder::decode($buffer);
                if (isset($test['decoded'])) {
                    $this->assertSame($test['decoded'], $result, $message);
                }
                $vardump = $this->dumpValue($result);
                $this->assertSame($test['vardump'], $vardump, $message);

                $this->assertArrayNotHasKey('error', $test, $message);
            } catch (CborException $exception) {
                $this->assertArrayHasKey('error', $test, $message);
                $this->assertContains($test['error'], $exception->getMessage(), $message);
            }
        }
    }

    private function dumpValue($result) : string
    {
        $result = $this->convertByteBuffers($result);
        ob_start();
        var_dump($result);
        return rtrim(ob_get_clean());
    }

    public function testInPlace()
    {
        $result = CborDecoder::decodeInPlace(
            HexData::buf(
                '
                01020304        # prefixed data (offset 0)
                83010203        # Cbor array (offset 4)
                08090A0B        # postfixed data (offset 8)
                '
            ),
            4,
            $endOffset
        );

        $this->assertSame([1, 2, 3], $result);
        $this->assertEquals(8, $endOffset);
    }

    public function testCorruptArray()
    {
        // Length 3 array but only 2 values
        $buf = HexData::buf(
            '83    # array(3)
                01 # unsigned(1)
                02 # unsigned(2)
            '
        );

        $this->expectException(CborException::class);
        CborDecoder::decode($buf);
    }

    public function testCorruptArrayInPlace()
    {
        // Length 3 array but only 2 values
        $buf = HexData::buf(
            '83    # array(3)
                01 # unsigned(1)
                02 # unsigned(2)
            '
        );

        $this->expectException(CborException::class);
        CborDecoder::decodeInPlace($buf, 0);
    }

    public function testUnsupportedMapKey()
    {
        // array as map key
        $buf = HexData::buf(
            'A1       # map(1)
                80    # array(0)
                61    # text(1)
                   62 # "b"
            '
        );

        $this->expectException(CborException::class);
        $this->expectExceptionMessageRegExp('~map key~i');
        CborDecoder::decode($buf);
    }

    public function testUnsupportedIndefiniteLength()
    {
        // Valid indefinite array but not supported
        $buf = HexData::buf(
            '9F    # array(*)
               01 # unsigned(1)
               02 # unsigned(2)
               FF # primitive(*)
            '
        );

        $this->expectException(CborException::class);
        $this->expectExceptionMessageRegExp('~indefinite~i');
        CborDecoder::decode($buf);
    }

    public function testReservedFloat()
    {
        $buf = HexData::buf('FE');

        $this->expectException(CborException::class);
        $this->expectExceptionMessageRegExp('~reserved~i');
        CborDecoder::decode($buf);
    }

    public function testBreakOutsideIndefinite()
    {
        // array as map key
        $buf = HexData::buf('FF');

        $this->expectException(CborException::class);
        $this->expectExceptionMessageRegExp('~indefinite~i');
        CborDecoder::decode($buf);
    }

    public function testReserved()
    {
        // array as map key
        $buf = HexData::buf('1E');
        $this->expectException(CborException::class);
        $this->expectExceptionMessageRegExp('~reserved~i');

        CborDecoder::decode($buf);
    }

    public function testAdditionalData()
    {
        // integer 15 followed by extra byte
        $buf = HexData::buf('1020');
        $this->expectException(CborException::class);
        $this->expectExceptionMessageRegExp('~unused bytes~i');
        CborDecoder::decode($buf);
    }

    public function testEncodeInteger()
    {
        $this->assertSame('00', bin2hex(CborEncoder::encodeInteger(0)));

        $this->assertSame('01', bin2hex(CborEncoder::encodeInteger(1)));
        $this->assertSame('17', bin2hex(CborEncoder::encodeInteger(23)));
        $this->assertSame('1818', bin2hex(CborEncoder::encodeInteger(24)));
        $this->assertSame('18ff', bin2hex(CborEncoder::encodeInteger(255)));
        $this->assertSame('190100', bin2hex(CborEncoder::encodeInteger(256)));
        $this->assertSame('19ffff', bin2hex(CborEncoder::encodeInteger(65535)));
        $this->assertSame('1a00010000', bin2hex(CborEncoder::encodeInteger(65536)));
        if (PHP_INT_SIZE > 4) {
            $this->assertSame('1affffffff', bin2hex(CborEncoder::encodeInteger(4294967295)));
            $this->assertSame('1b0000000100000000', bin2hex(CborEncoder::encodeInteger(4294967296)));
        }

        $this->assertSame('20', bin2hex(CborEncoder::encodeInteger(-1)));
        $this->assertSame('37', bin2hex(CborEncoder::encodeInteger(-24)));
        $this->assertSame('3818', bin2hex(CborEncoder::encodeInteger(-25)));
        $this->assertSame('38ff', bin2hex(CborEncoder::encodeInteger(-256)));
        $this->assertSame('390100', bin2hex(CborEncoder::encodeInteger(-257)));
        $this->assertSame('39ffff', bin2hex(CborEncoder::encodeInteger(-65536)));
        if (PHP_INT_SIZE > 4) {
            $this->assertSame('3affffffff', bin2hex(CborEncoder::encodeInteger(-4294967296)));
            $this->assertSame('3b0000000100000000', bin2hex(CborEncoder::encodeInteger(-4294967297)));
        }
    }

    public function testEncodeText()
    {
        $this->assertSame('60', bin2hex(CborEncoder::encodeTextString('')));
        $this->assertSame('6174', bin2hex(CborEncoder::encodeTextString('t')));
        $this->assertSame('6a74657374737472696e67', bin2hex(CborEncoder::encodeTextString('teststring')));
    }

    public function testEncodeBytes()
    {
        $this->assertSame('40', bin2hex(CborEncoder::encodeByteString(new ByteBuffer(''))));
        $this->assertSame('421234', bin2hex(CborEncoder::encodeByteString(ByteBuffer::fromHex('1234'))));
        $this->assertSame('481234567890123456', bin2hex(CborEncoder::encodeByteString(ByteBuffer::fromHex('1234567890123456'))));
    }

    public function testEncodeMapValues()
    {
        $vals = [];

        $vals[hex2bin('63616161')] = hex2bin('617A');  // "aaa" : "z"
        $vals[hex2bin('626462')] = hex2bin('6179');    // "db" : "y"
        $vals[hex2bin('05')] = hex2bin('F4');          //  5   : false
        $vals[hex2bin('626461')] = hex2bin('6178');    // "da" : "x"
        $vals[hex2bin('21')] = hex2bin('F6');          // -2 : null

        // Should be sorted according to canonical Cbor

        $validCbor =
            HexData::bin('
                A5              # map(5)
                05              # 5 
                    F4          #       false
                21              # -2
                    F6          #       null
                62 64 61        # da
                    61 78       #       x
                62 64 62        # db
                    61 79       #       y
                63 61 61 61     # aaa
                    617A        #       z

            ');

        $this->assertSame(bin2hex($validCbor), bin2hex(CborEncoder::encodeMapValues($vals)));
    }

    public function testEncodeMap()
    {
        $map =
        [
            'cc' => 'dd',
             25 => 1,
             'd' => ByteBuffer::fromHex('1234'),
             23 => 2,
             'a' => 'b',
        ];

        $this->assertSame('a51702181901616161626164421234626363626464', bin2hex(CborEncoder::encodeMap($map)));
    }

    public function testDuplicateMapKey()
    {
        // array as map key
        $buf = HexData::buf(
            'A3       # map(3)
                   01    # unsigned(1)
                   61    # text(1)
                      62 # "b"
                   02    # unsigned(2)
                   61    # text(1)
                      64 # "d"
                   01    # unsigned(1)
                   61    # text(1)
                      65 # "e"
                '
        );

        $this->expectException(CborException::class);
        $this->expectExceptionMessageRegExp('~duplicate key~i');
        CborDecoder::decode($buf);
    }
}

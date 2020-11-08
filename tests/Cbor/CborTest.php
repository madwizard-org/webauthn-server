<?php

namespace MadWizard\WebAuthn\Tests\Cbor;

use MadWizard\WebAuthn\Exception\CborException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Format\CborDecoder;
use MadWizard\WebAuthn\Format\CborEncoder;
use MadWizard\WebAuthn\Format\CborMap;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;
use MadWizard\WebAuthn\Tests\Helper\HexData;
use PHPUnit\Framework\TestCase;
use function bin2hex;
use function json_decode;
use function var_dump;
use const PHP_INT_SIZE;

class CborTest extends TestCase
{
    private function convertObjects($value)
    {
        if ($value instanceof ByteBuffer) {
            return 'HEX:' . bin2hex($value->getBinaryString());
        }
        if ($value instanceof CborMap) {
            $c = [];
            foreach ($value->getEntries() as [$k, $v]) {
                $c[$k] = $v;
            }
            $value = $c;
        }

        if (!is_array($value)) {
            return $value;
        }

        return array_map([$this, 'convertObjects'], $value);
    }

    public function testVectors()
    {
        $tests = json_decode(FixtureHelper::getFixtureContent('Cbor/testvectors.json'), true);

        foreach ($tests as $test) {
            $message = sprintf('Cbor hex: ' . $test['hex']);

            $buffer = ByteBuffer::fromHex($test['hex']);

            $errorMessage = null;
            try {
                $result = $this->convertObjects(CborDecoder::decode($buffer));

                if (isset($test['decoded'])) {
                    self::assertSame($test['decoded'], $result, $message);
                }
                $vardump = $this->dumpValue($result);
                self::assertSame($test['vardump'], $vardump, $message);

                self::assertArrayNotHasKey('error', $test, $message);
            } catch (CborException $exception) {
                self::assertArrayHasKey('error', $test, $message);
                self::assertStringContainsString($test['error'], $exception->getMessage(), $message);
            }
        }
    }

    private function dumpValue($result): string
    {
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

        self::assertSame([1, 2, 3], $result);
        self::assertEquals(8, $endOffset);
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
        $this->expectExceptionMessageMatches('~map key~i');
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
        $this->expectExceptionMessageMatches('~indefinite~i');
        CborDecoder::decode($buf);
    }

    public function testReservedFloat()
    {
        $buf = HexData::buf('FE');

        $this->expectException(CborException::class);
        $this->expectExceptionMessageMatches('~reserved~i');
        CborDecoder::decode($buf);
    }

    public function testBreakOutsideIndefinite()
    {
        // array as map key
        $buf = HexData::buf('FF');

        $this->expectException(CborException::class);
        $this->expectExceptionMessageMatches('~indefinite~i');
        CborDecoder::decode($buf);
    }

    public function testReserved()
    {
        // array as map key
        $buf = HexData::buf('1E');
        $this->expectException(CborException::class);
        $this->expectExceptionMessageMatches('~reserved~i');

        CborDecoder::decode($buf);
    }

    public function testAdditionalData()
    {
        // integer 15 followed by extra byte
        $buf = HexData::buf('1020');
        $this->expectException(CborException::class);
        $this->expectExceptionMessageMatches('~unused bytes~i');
        CborDecoder::decode($buf);
    }

    public function testEncodeInteger()
    {
        self::assertSame('00', bin2hex(CborEncoder::encodeInteger(0)));

        self::assertSame('01', bin2hex(CborEncoder::encodeInteger(1)));
        self::assertSame('17', bin2hex(CborEncoder::encodeInteger(23)));
        self::assertSame('1818', bin2hex(CborEncoder::encodeInteger(24)));
        self::assertSame('18ff', bin2hex(CborEncoder::encodeInteger(255)));
        self::assertSame('190100', bin2hex(CborEncoder::encodeInteger(256)));
        self::assertSame('19ffff', bin2hex(CborEncoder::encodeInteger(65535)));
        self::assertSame('1a00010000', bin2hex(CborEncoder::encodeInteger(65536)));
        if (PHP_INT_SIZE > 4) {
            self::assertSame('1affffffff', bin2hex(CborEncoder::encodeInteger(4294967295)));
            self::assertSame('1b0000000100000000', bin2hex(CborEncoder::encodeInteger(4294967296)));
        }

        self::assertSame('20', bin2hex(CborEncoder::encodeInteger(-1)));
        self::assertSame('37', bin2hex(CborEncoder::encodeInteger(-24)));
        self::assertSame('3818', bin2hex(CborEncoder::encodeInteger(-25)));
        self::assertSame('38ff', bin2hex(CborEncoder::encodeInteger(-256)));
        self::assertSame('390100', bin2hex(CborEncoder::encodeInteger(-257)));
        self::assertSame('39ffff', bin2hex(CborEncoder::encodeInteger(-65536)));
        if (PHP_INT_SIZE > 4) {
            self::assertSame('3affffffff', bin2hex(CborEncoder::encodeInteger(-4294967296)));
            self::assertSame('3b0000000100000000', bin2hex(CborEncoder::encodeInteger(-4294967297)));
        }
    }

    public function testEncodeText()
    {
        self::assertSame('60', bin2hex(CborEncoder::encodeTextString('')));
        self::assertSame('6174', bin2hex(CborEncoder::encodeTextString('t')));
        self::assertSame('6a74657374737472696e67', bin2hex(CborEncoder::encodeTextString('teststring')));
    }

    public function testEncodeBytes()
    {
        self::assertSame('40', bin2hex(CborEncoder::encodeByteString(new ByteBuffer(''))));
        self::assertSame('421234', bin2hex(CborEncoder::encodeByteString(ByteBuffer::fromHex('1234'))));
        self::assertSame('481234567890123456', bin2hex(CborEncoder::encodeByteString(ByteBuffer::fromHex('1234567890123456'))));
    }

    public function testCanonicalMapValues()
    {
        $map = new CborMap();

        $map->set('aaa', 'z');
        $map->set('db', 'y');
        $map->set(5, false);
        $map->set('da', 'x');
        $map->set(-2, null);
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

        self::assertSame(bin2hex($validCbor), bin2hex(CborEncoder::encodeMap($map)));
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

        self::assertSame('a51702181901616161626164421234626363626464', bin2hex(CborEncoder::encodeMap(CborMap::fromArray($map))));
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
        $this->expectExceptionMessageMatches('~duplicate key~i');
        CborDecoder::decode($buf);
    }
}

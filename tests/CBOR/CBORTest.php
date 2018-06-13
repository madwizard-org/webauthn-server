<?php


namespace MadWizard\WebAuthn\Tests\CBOR;

use MadWizard\WebAuthn\Exception\CBORException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Format\CBOR;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;
use MadWizard\WebAuthn\Tests\Helper\HexData;
use PHPUnit\Framework\TestCase;
use function json_decode;

class CBORTest extends TestCase
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
        $tests = json_decode(FixtureHelper::getFixtureContent('CBOR/testvectors.json'), true);

        foreach ($tests as $test) {
            $message = sprintf('CBOR hex: ' . $test['hex']);

            $buffer = ByteBuffer::fromHex($test['hex']);

            $errorMessage = null;
            try {
                $result = CBOR::decode($buffer);
                if (isset($test['decoded'])) {
                    $this->assertSame($test['decoded'], $result, $message);
                }
                $vardump = $this->dumpValue($result);
                $this->assertSame($test['vardump'], $vardump, $message);

                $this->assertArrayNotHasKey('error', $test, $message);
            } catch (CBORException $exception) {
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
        $result = CBOR::decodeInPlace(
            HexData::buf(
                '
                01020304        # prefixed data (offset 0)
                83010203        # CBOR array (offset 4)
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

        $this->expectException(CBORException::class);
        CBOR::decode($buf);
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

        $this->expectException(CBORException::class);
        CBOR::decodeInPlace($buf, 0);
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

        $this->expectException(CBORException::class);
        $this->expectExceptionMessageRegExp('~map key~i');
        CBOR::decode($buf);
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

        $this->expectException(CBORException::class);
        $this->expectExceptionMessageRegExp('~indefinite~i');
        CBOR::decode($buf);
    }

    public function testReservedFloat()
    {
        $buf = HexData::buf('FE');

        $this->expectException(CBORException::class);
        $this->expectExceptionMessageRegExp('~reserved~i');
        CBOR::decode($buf);
    }

    public function testBreakOutsideIndefinite()
    {
        // array as map key
        $buf = HexData::buf('FF');

        $this->expectException(CBORException::class);
        $this->expectExceptionMessageRegExp('~indefinite~i');
        CBOR::decode($buf);
    }

    public function testReserved()
    {
        // array as map key
        $buf = HexData::buf('1E');
        $this->expectException(CBORException::class);
        $this->expectExceptionMessageRegExp('~reserved~i');

        CBOR::decode($buf);
    }

    public function testAdditionalData()
    {
        // integer 15 followed by extra byte
        $buf = HexData::buf('1020');
        $this->expectException(CBORException::class);
        $this->expectExceptionMessageRegExp('~unused bytes~i');
        CBOR::decode($buf);
    }
}

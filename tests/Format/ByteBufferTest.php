<?php

namespace MadWizard\WebAuthn\Tests\Format;

use const PHP_INT_SIZE;
use MadWizard\WebAuthn\Format\ByteBuffer;
use PHPUnit\Framework\TestCase;
use function hex2bin;

class ByteBufferTest extends TestCase
{
    public function testIsEmpty()
    {
        $empty = new ByteBuffer('');
        $notEmpty = new ByteBuffer('a');
        $this->assertTrue($empty->isEmpty());
        $this->assertFalse($notEmpty->isEmpty());
    }

    public function testGetLength()
    {
        $empty = new ByteBuffer('');
        $len4 = new ByteBuffer('abcd');
        $this->assertSame(0, $empty->getLength());
        $this->assertSame(4, $len4->getLength());
    }

    public function testRandomBuffer()
    {
        $buf = ByteBuffer::randomBuffer(100);
        $this->assertSame(100, strlen($buf->getBinaryString()));
    }

    public function testFromHex()
    {
        $buf = ByteBuffer::fromHex('abcdef0102');
        $this->assertSame(hex2bin('abcdef0102'), $buf->getBinaryString());
    }

    public function testGetBytes()
    {
        $binaryString = 'abc' . hex2bin('00010203') . 'efg';
        $data = new ByteBuffer($binaryString);
        $this->assertSame("abc\x00", $data->getBytes(0, 4));
        $this->assertSame("\x00\x01", $data->getBytes(3, 2));
        $this->assertSame('', $data->getBytes(3, 0));
        $this->assertSame("\x02\x03ef", $data->getBytes(5, 4));
    }

    /**
     * @expectedException \MadWizard\WebAuthn\Exception\ByteBufferException
     */
    public function testGetBytesBoundsOffset()
    {
        $binaryString = 'abcefg';
        $data = new ByteBuffer($binaryString);
        $data->getBytes(6, 1);
    }

    /**
     * @expectedException \MadWizard\WebAuthn\Exception\ByteBufferException
     */
    public function testGetBytesBoundsLength()
    {
        $binaryString = 'abcefg';
        $data = new ByteBuffer($binaryString);
        $data->getBytes(4, 3);
    }

    public function testGetByteVal()
    {
        $buf = new ByteBuffer('ABCDEF');

        $this->assertSame(ord('A'), $buf->getByteVal(0));
        $this->assertSame(ord('E'), $buf->getByteVal(4));
    }

    /**
     * @expectedException \MadWizard\WebAuthn\Exception\ByteBufferException
     */
    public function testGetByteValBounds()
    {
        $buf = new ByteBuffer('ABCDEF');
        $buf->getByteVal(6);
    }

    public function testGetUint16Val()
    {
        $buf = new ByteBuffer("a\x12\x34");

        $this->assertSame(0x1234, $buf->getUint16Val(1));
    }

    /**
     * @expectedException \MadWizard\WebAuthn\Exception\ByteBufferException
     */
    public function testGetUint16ValBoundsOffset()
    {
        $buf = new ByteBuffer('abc');
        $buf->getUint16Val(4);
    }

    /**
     * @expectedException \MadWizard\WebAuthn\Exception\ByteBufferException
     */
    public function testGetUint16ValBoundsLength()
    {
        $buf = new ByteBuffer('abc');
        $buf->getUint16Val(2);
    }

    public function testGetUint32Val()
    {
        $buf = new ByteBuffer('a' . hex2bin('12345678'));


        $this->assertSame(0x12345678, $buf->getUint32Val(1));
    }

    /**
     * @expectedException \MadWizard\WebAuthn\Exception\ByteBufferException
     */
    public function testGetUint32ValBoundsOffset()
    {
        $buf = new ByteBuffer('abc');
        $buf->getUint32Val(4);
    }

    /**
     * @expectedException \MadWizard\WebAuthn\Exception\ByteBufferException
     */
    public function testGetUint32ValBoundsLength()
    {
        $buf = new ByteBuffer('abcd');
        $buf->getUint32Val(1);
    }

    /**
     * @expectedException \MadWizard\WebAuthn\Exception\ByteBufferException
     */
    public function testGetUint32ValLimits()
    {
        if (PHP_INT_SIZE !== 4) {
            $this->markTestSkipped('No 32 bits ints');
            return;
        }

        $buf = new ByteBuffer(hex2bin('80000000'));

        $buf->getUint32Val(0);
    }

    public function testGetUint64Val()
    {
        if (PHP_INT_SIZE !== 8) {
            $this->markTestSkipped('No 64 bits ints');
            return;
        }
        $buf = new ByteBuffer('a' . hex2bin('12345678ABCDEF00'));

        $this->assertSame(0x12345678ABCDEF00, $buf->getUint64Val(1));
    }

    /**
     * @expectedException \MadWizard\WebAuthn\Exception\ByteBufferException
     */
    public function testGetUint64ValLimits()
    {
        if (PHP_INT_SIZE !== 8) {
            $this->markTestSkipped('No 64 bits ints');
            return;
        }

        $buf = new ByteBuffer(hex2bin('8000000000000000'));

        $buf->getUint64Val(0);
    }

    /**
     * @expectedException \MadWizard\WebAuthn\Exception\ByteBufferException
     */
    public function testGetUint64ValBoundsOffset()
    {
        $buf = new ByteBuffer('abc');
        $buf->getUint64Val(4);
    }

    /**
     * @expectedException \MadWizard\WebAuthn\Exception\ByteBufferException
     */
    public function testGetUint64ValBoundsLength()
    {
        $buf = new ByteBuffer('abcdefgh');
        $buf->getUint64Val(1);
    }

    public function testGetFloatVal()
    {
        $buf = new ByteBuffer("a\x40\x49\x0f\xdb");
        $this->assertEquals(3.14159274102, $buf->getFloatVal(1));

        $buf = new ByteBuffer("a\x7f\x80\x00\x00");

        $result = $buf->getFloatVal(1);
        $this->assertInfinite($result);
        $this->assertGreaterThan(0, $result);
    }

    /**
     * @expectedException \MadWizard\WebAuthn\Exception\ByteBufferException
     */
    public function testGetFloatValBoundsOffset()
    {
        $buf = new ByteBuffer('abc');
        $buf->getFloatVal(4);
    }

    /**
     * @expectedException \MadWizard\WebAuthn\Exception\ByteBufferException
     */
    public function testGetFloatValBoundsLength()
    {
        $buf = new ByteBuffer('abcd');
        $buf->getFloatVal(1);
    }

    public function testGetDoubleVal()
    {
        $buf = new ByteBuffer("a\x40\xa4\x0f\x1e\xff\x89\x92\x83");
        $this->assertSame(2567.56054334558, $buf->getDoubleVal(1));

        $buf = new ByteBuffer("a\xff\xf0\x00\x00\x00\x00\x00\x00"); // -INF
        $result = $buf->getDoubleVal(1);
        $this->assertInfinite($result);
        $this->assertLessThan(0, $result);
    }

    /**
     * @expectedException \MadWizard\WebAuthn\Exception\ByteBufferException
     */
    public function testGetDoubleValBoundsOffset()
    {
        $buf = new ByteBuffer('abc');
        $buf->getDoubleVal(4);
    }

    /**
     * @expectedException \MadWizard\WebAuthn\Exception\ByteBufferException
     */
    public function testGetDoubleValBoundsLength()
    {
        $buf = new ByteBuffer('abc');
        $buf->getDoubleVal(2);
    }

    public function testGetHalfFloatVal()
    {
        $testHalf = function (string $hex) {
            $buf = new ByteBuffer('a' . hex2bin($hex));
            return $buf->getHalfFloatVal(1);
        };

        // Test vectors from wikipedia Half-precision_floating-point_format
        $this->assertSame(1.0, $testHalf('3C00'));

        $this->assertSame(1.0009765625, $testHalf('3C01')); // next smallest float after 1
        $this->assertSame(-2.0, $testHalf('C000'));
        $this->assertSame(65504.0, $testHalf('7BFF')); // max half precision

        $this->assertSame(6.10352e-5, $testHalf('0400')); // minimum positive normal
        $this->assertSame(6.097562e-5, $testHalf('03FF')); // maximum subnormal
        $this->assertSame(5.96046e-8, $testHalf('0001')); // minimum positive subnormal

        $this->assertSame(0.0, $testHalf('0000')); // 0
        $this->assertSame(-0.0, $testHalf('8000')); // -0

        $this->assertNan($testHalf('7E00')); // NaN
        $inf = $testHalf('7C00');
        $this->assertInfinite($inf);
        $this->assertGreaterThan(0, $inf);

        $negInf = $testHalf('FC00');
        $this->assertInfinite($negInf);
        $this->assertLessThan(0, $negInf);


        $this->assertSame(0.333251953125, $testHalf('3555')); // 0.333251953125 ≈ 1/3
    }

    /**
     * @expectedException \MadWizard\WebAuthn\Exception\ByteBufferException
     */
    public function testGetHalfFloatValBoundsOffset()
    {
        $buf = new ByteBuffer('abc');
        $buf->getHalfFloatVal(3);
    }

    /**
     * @expectedException \MadWizard\WebAuthn\Exception\ByteBufferException
     */
    public function testGetHalfFloatValBoundsLength()
    {
        $buf = new ByteBuffer('abc');
        $buf->getHalfFloatVal(2);
    }

    public function testGetBinaryString()
    {
        $binaryString = "abc\x00\x01\x02\x03efg";
        $data = new ByteBuffer($binaryString);
        $this->assertSame($binaryString, $data->getBinaryString());
    }
}

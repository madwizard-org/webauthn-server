<?php

namespace MadWizard\WebAuthn\Tests\Format;

use InvalidArgumentException;
use MadWizard\WebAuthn\Exception\ByteBufferException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use PHPUnit\Framework\TestCase;
use function bin2hex;
use function hex2bin;
use function unserialize;
use const PHP_INT_SIZE;

class ByteBufferTest extends TestCase
{
    public function testIsEmpty()
    {
        $empty = new ByteBuffer('');
        $notEmpty = new ByteBuffer('a');
        self::assertTrue($empty->isEmpty());
        self::assertFalse($notEmpty->isEmpty());
    }

    public function testGetLength()
    {
        $empty = new ByteBuffer('');
        $len4 = new ByteBuffer('abcd');
        self::assertSame(0, $empty->getLength());
        self::assertSame(4, $len4->getLength());
    }

    public function testRandomBuffer()
    {
        $buf = ByteBuffer::randomBuffer(100);
        self::assertSame(100, strlen($buf->getBinaryString()));
    }

    public function testFromHex()
    {
        $buf = ByteBuffer::fromHex('abcdef0102');
        self::assertSame(hex2bin('abcdef0102'), $buf->getBinaryString());

        $buf = ByteBuffer::fromHex('ABCDEF0102');
        self::assertSame(hex2bin('ABCDEF0102'), $buf->getBinaryString());
    }

    public function testGetBytes()
    {
        $binaryString = 'abc' . hex2bin('00010203') . 'efg';
        $data = new ByteBuffer($binaryString);
        self::assertSame("abc\x00", $data->getBytes(0, 4));
        self::assertSame("\x00\x01", $data->getBytes(3, 2));
        self::assertSame('', $data->getBytes(3, 0));
        self::assertSame("\x02\x03ef", $data->getBytes(5, 4));
    }

    public function testGetBytesBoundsOffset()
    {
        $this->expectException(ByteBufferException::class);
        $binaryString = 'abcefg';
        $data = new ByteBuffer($binaryString);
        $data->getBytes(6, 1);
    }

    public function testGetBytesBoundsLength()
    {
        $this->expectException(ByteBufferException::class);
        $binaryString = 'abcefg';
        $data = new ByteBuffer($binaryString);
        $data->getBytes(4, 3);
    }

    public function testGetByteVal()
    {
        $buf = new ByteBuffer('ABCDEF');

        self::assertSame(ord('A'), $buf->getByteVal(0));
        self::assertSame(ord('E'), $buf->getByteVal(4));
    }

    public function testGetByteValBounds()
    {
        $this->expectException(ByteBufferException::class);
        $buf = new ByteBuffer('ABCDEF');
        $buf->getByteVal(6);
    }

    public function testGetUint16Val()
    {
        $buf = new ByteBuffer("a\x12\x34");

        self::assertSame(0x1234, $buf->getUint16Val(1));
    }

    public function testGetUint16ValBoundsOffset()
    {
        $this->expectException(ByteBufferException::class);
        $buf = new ByteBuffer('abc');
        $buf->getUint16Val(4);
    }

    public function testGetUint16ValBoundsLength()
    {
        $this->expectException(ByteBufferException::class);
        $buf = new ByteBuffer('abc');
        $buf->getUint16Val(2);
    }

    public function testGetUint32Val()
    {
        $buf = new ByteBuffer('a' . hex2bin('12345678'));

        self::assertSame(0x12345678, $buf->getUint32Val(1));
    }

    public function testGetUint32ValBoundsOffset()
    {
        $this->expectException(ByteBufferException::class);
        $buf = new ByteBuffer('abc');
        $buf->getUint32Val(4);
    }

    public function testGetUint32ValBoundsLength()
    {
        $this->expectException(ByteBufferException::class);
        $buf = new ByteBuffer('abcd');
        $buf->getUint32Val(1);
    }

    public function testGetUint32ValLimits()
    {
        if (PHP_INT_SIZE !== 4) {
            $this->markTestSkipped('No 32 bits ints');
            return;
        }
        $this->expectException(ByteBufferException::class);

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

        self::assertSame(0x12345678ABCDEF00, $buf->getUint64Val(1));
    }

    public function testGetUint64ValLimits()
    {
        if (PHP_INT_SIZE !== 8) {
            $this->markTestSkipped('No 64 bits ints');
            return;
        }

        $this->expectException(ByteBufferException::class);

        $buf = new ByteBuffer(hex2bin('8000000000000000'));

        $buf->getUint64Val(0);
    }

    public function testGetUint64ValBoundsOffset()
    {
        $this->expectException(ByteBufferException::class);
        $buf = new ByteBuffer('abc');
        $buf->getUint64Val(4);
    }

    public function testGetUint64ValBoundsLength()
    {
        $this->expectException(ByteBufferException::class);
        $buf = new ByteBuffer('abcdefgh');
        $buf->getUint64Val(1);
    }

    public function testGetFloatVal()
    {
        $buf = new ByteBuffer("a\x40\x49\x0f\xdb");
        self::assertEquals(3.1415927410125732, $buf->getFloatVal(1));

        $buf = new ByteBuffer("a\x7f\x80\x00\x00");

        $result = $buf->getFloatVal(1);
        self::assertInfinite($result);
        self::assertGreaterThan(0, $result);
    }

    public function testGetFloatValBoundsOffset()
    {
        $this->expectException(ByteBufferException::class);
        $buf = new ByteBuffer('abc');
        $buf->getFloatVal(4);
    }

    public function testGetFloatValBoundsLength()
    {
        $this->expectException(ByteBufferException::class);

        $buf = new ByteBuffer('abcd');
        $buf->getFloatVal(1);
    }

    public function testGetDoubleVal()
    {
        $buf = new ByteBuffer("a\x40\xa4\x0f\x1e\xff\x89\x92\x83");
        self::assertSame(2567.56054334558, $buf->getDoubleVal(1));

        $buf = new ByteBuffer("a\xff\xf0\x00\x00\x00\x00\x00\x00"); // -INF
        $result = $buf->getDoubleVal(1);
        self::assertInfinite($result);
        self::assertLessThan(0, $result);
    }

    public function testGetDoubleValBoundsOffset()
    {
        $this->expectException(ByteBufferException::class);
        $buf = new ByteBuffer('abc');
        $buf->getDoubleVal(4);
    }

    public function testGetDoubleValBoundsLength()
    {
        $this->expectException(ByteBufferException::class);
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
        self::assertSame(1.0, $testHalf('3C00'));

        self::assertSame(1.0009765625, $testHalf('3C01')); // next smallest float after 1
        self::assertSame(-2.0, $testHalf('C000'));
        self::assertSame(65504.0, $testHalf('7BFF')); // max half precision

        self::assertSame(0.00006103515625, $testHalf('0400')); // minimum positive normal
        self::assertSame(0.00006097555160522461, $testHalf('03FF')); // maximum subnormal
        self::assertSame(5.960464477539063e-8, $testHalf('0001')); // minimum positive subnormal

        self::assertSame(0.0, $testHalf('0000')); // 0
        self::assertSame(-0.0, $testHalf('8000')); // -0

        self::assertNan($testHalf('7E00')); // NaN
        $inf = $testHalf('7C00');
        self::assertInfinite($inf);
        self::assertGreaterThan(0, $inf);

        $negInf = $testHalf('FC00');
        self::assertInfinite($negInf);
        self::assertLessThan(0, $negInf);

        self::assertSame(0.333251953125, $testHalf('3555')); // 0.333251953125 ≈ 1/3
    }

    public function testGetHalfFloatValBoundsOffset()
    {
        $this->expectException(ByteBufferException::class);
        $buf = new ByteBuffer('abc');
        $buf->getHalfFloatVal(3);
    }

    public function testGetHalfFloatValBoundsLength()
    {
        $this->expectException(ByteBufferException::class);
        $buf = new ByteBuffer('abc');
        $buf->getHalfFloatVal(2);
    }

    public function testGetBinaryString()
    {
        $binaryString = "abc\x00\x01\x02\x03efg";
        $data = new ByteBuffer($binaryString);
        self::assertSame($binaryString, $data->getBinaryString());
    }

    public function testGetHex()
    {
        $data = ByteBuffer::fromHex('12ab09cf');
        self::assertSame('12ab09cf', $data->getHex());
    }

    public function testEquals()
    {
        self::assertTrue(ByteBuffer::fromHex('aabb00cc')->equals(ByteBuffer::fromHex('aabb00cc')));
        self::assertFalse(ByteBuffer::fromHex('aabb00cc')->equals(ByteBuffer::fromHex('aabb11cc')));
    }

    public function testSerialize()
    {
        $buffer = ByteBuffer::fromHex('00AABBCC00EEFF');
        $serialized = serialize($buffer);

        /**
         * @var ByteBuffer $result
         */
        $result = unserialize($serialized);
        self::assertTrue($result->equals($buffer));
        self::assertSame($buffer->getLength(), $result->getLength());
    }

    public function testInvalidHex()
    {
        $this->expectException(InvalidArgumentException::class);
        ByteBuffer::fromHex('zz');
    }

    public function testInvalidHexLenth()
    {
        $this->expectException(InvalidArgumentException::class);
        ByteBuffer::fromHex('aab');
    }

    public function testFromBase64Url()
    {
        self::assertSame(bin2hex('abcd'), ByteBuffer::fromBase64Url('YWJjZA')->getHex());
        self::assertSame('', ByteBuffer::fromBase64Url('')->getHex());
    }

    public function testGetBase64Url()
    {
        self::assertSame('YWJjZA', (new ByteBuffer('abcd'))->getBase64Url());
        self::assertSame('', (new ByteBuffer(''))->getBase64Url());
    }
}

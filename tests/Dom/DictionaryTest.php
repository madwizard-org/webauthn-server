<?php


namespace MadWizard\WebAuthn\Tests\Dom;

use MadWizard\WebAuthn\Dom\AbstractDictionary;
use MadWizard\WebAuthn\Format\ByteBuffer;
use PHPUnit\Framework\TestCase;

class DictionaryTest extends TestCase
{
    private function createDictionary(array $data) : AbstractDictionary
    {
        $mock = $this->getMockForAbstractClass(AbstractDictionary::class);

        $mock->expects($this->any())
            ->method('getAsArray')
            ->willReturn($data);

        return $mock;
    }

    private function checkJson(array $data, ?array $check = null)
    {
        $dict = $this->createDictionary($data);

        $this->assertSame($check === null ? $data : $check, $dict->getJSONData());
    }

    public function testSimple()
    {
        $this->checkJson([]);
        $this->checkJson(['a' => 'b']);
        $this->checkJson(['a' => 'b', 'c' => 5]);
        $this->checkJson(['a' => 'b', 'c' => ['d' => 'e']]);
    }

    public function testBuffer()
    {
        $this->checkJson(
            ['binary' => ByteBuffer::fromHex('45464748')],
            ['$buffer$binary' => 'RUZHSA']

        );
    }

    public function testNested()
    {
        $inner = $this->createDictionary(['x' => ByteBuffer::fromHex('C0FFEE')]);
        $nested = $this->createDictionary(['number' => 123, 'inner' => $inner]);
        $this->checkJson(
            ['a' => 'b', 'nested' => $nested],
            [
                'a' => 'b',
                'nested' =>
                [
                    'number' => 123,
                    'inner' =>
                        [
                            '$buffer$x' => 'wP_u'
                        ]
                ]
            ]
        );
    }
}

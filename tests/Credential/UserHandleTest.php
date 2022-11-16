<?php

namespace MadWizard\WebAuthn\Tests\Credential;

use InvalidArgumentException;
use MadWizard\WebAuthn\Credential\UserHandle;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use PHPUnit\Framework\TestCase;

class UserHandleTest extends TestCase
{
    private function checkId(UserHandle $id)
    {
        self::assertSame('3c4fbf08', bin2hex($id->toBinary()));
        self::assertSame('3c4fbf08', $id->toHex());
        self::assertSame('PE-_CA', $id->toString());
        self::assertTrue(ByteBuffer::fromHex('3c4fbf08')->equals($id->toBuffer()));
    }

    public function testString()
    {
        $id = UserHandle::fromString('PE-_CA');
        $this->checkId($id);
    }

    public function testHex()
    {
        $id = UserHandle::fromHex('3c4fbf08');
        $this->checkId($id);
    }

    public function testInvalidHex()
    {
        $this->expectException(InvalidArgumentException::class); //TODO webauth exception?
        UserHandle::fromHex('sg');
    }

    public function testBuffer()
    {
        $id = UserHandle::fromBuffer(ByteBuffer::fromHex('3c4fbf08'));
        $this->checkId($id);
    }

    public function testBinary()
    {
        $id = UserHandle::fromBinary("\x3c\x4f\xbf\x08");
        $this->checkId($id);
    }

    public function testLength()
    {
        $this->expectException(WebAuthnException::class);
        UserHandle::fromBinary(str_pad('x', UserHandle::MAX_USER_HANDLE_BYTES + 1));
    }

    public function testEquals()
    {
        $id1 = UserHandle::fromHex('3c4fbf08');
        $id2 = UserHandle::fromHex('3c4fbf08');
        $id3 = UserHandle::fromHex('3c4fbf09');
        self::assertTrue($id1->equals($id1));
        self::assertTrue($id1->equals($id2));
        self::assertFalse($id2->equals($id3));
    }

    /**
     * @param callable():void $fn
     *
     * @dataProvider emptyCalls
     */
    public function testDisallowEmpty(callable $fn): void
    {
        $this->expectException(WebAuthnException::class);
        $this->expectDeprecationMessageMatches('~not be empty~');
        $fn();
    }

    public function emptyCalls()
    {
        return [
            'string' => [function () { UserHandle::fromString(''); }],
            'buffer' => [function () { UserHandle::fromBuffer(new ByteBuffer('')); }],
            'hex' => [function () { UserHandle::fromHex(''); }],
            'binary' => [function () { UserHandle::fromBinary(''); }],
            'constructor' => [function () {
                (new class() extends UserHandle {
                    public function __construct()
                    {
                        parent::__construct('');
                    }
                })();
            },
        ], ];
    }
}

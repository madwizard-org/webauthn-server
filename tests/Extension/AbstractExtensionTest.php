<?php

namespace MadWizard\WebAuthn\Tests\Extension;

use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Extension\AbstractExtensionInput;
use MadWizard\WebAuthn\Extension\AbstractExtensionOutput;
use PHPUnit\Framework\TestCase;

class AbstractExtensionTest extends TestCase
{
    public function testExtensionInput()
    {
        /**
         * @var AbstractExtensionInput $ext
         */
        $ext = $this->getMockForAbstractClass(AbstractExtensionInput::class, [
            'validIdentifier',
        ]);

        $this->assertNull($ext->getInput());
        $this->assertSame('validIdentifier', $ext->getIdentifier());
    }

    public function testInvalidIdentifierInput()
    {
        $this->expectException(WebAuthnException::class);
        $this->expectExceptionMessageMatches('~identifier~');
        $this->getMockForAbstractClass(AbstractExtensionInput::class, [
            'not valid',
        ]);
    }

    public function testExtensionOutput()
    {
        /**
         * @var AbstractExtensionOutput $ext
         */
        $ext = $this->getMockForAbstractClass(AbstractExtensionOutput::class, [
            'validIdentifier',
        ]);

        $this->assertNull($ext->getOutput());
        $this->assertSame('validIdentifier', $ext->getIdentifier());
    }

    public function testInvalidIdentifierOutput()
    {
        $this->expectException(WebAuthnException::class);
        $this->expectExceptionMessageMatches('~identifier~');
        $this->getMockForAbstractClass(AbstractExtensionOutput::class, [
            'not valid',
        ]);
    }
}

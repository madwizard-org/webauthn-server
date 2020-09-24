<?php

namespace MadWizard\WebAuthn\Conformance\Extension;

use MadWizard\WebAuthn\Extension\ExtensionInterface;
use MadWizard\WebAuthn\Extension\ExtensionProcessingContext;
use PHPUnit\Framework\TestCase;

class ExtensionProcessingContextTest extends TestCase
{
    /**
     * @var ExtensionProcessingContext
     */
    private $context;

    public function setUp(): void
    {
        $this->context = new ExtensionProcessingContext(ExtensionInterface::OPERATION_AUTHENTICATION);
    }

    public function testOperation()
    {
        self::assertSame(ExtensionInterface::OPERATION_AUTHENTICATION, $this->context->getOperation());
    }

    public function testOverruledRpId()
    {
        self::assertNull($this->context->getOverruledRpId());
        $this->context->setOverruledRpId('https://localhost');
        self::assertSame('https://localhost', $this->context->getOverruledRpId());
    }

//
//    public function testAddOutput() TODO
//    {
//
//    }
}

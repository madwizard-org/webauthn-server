<?php

namespace MadWizard\WebAuthn\Tests\Extension\Generic;

use MadWizard\WebAuthn\Extension\ExtensionResponse;
use MadWizard\WebAuthn\Extension\Generic\GenericExtensionInput;
use MadWizard\WebAuthn\Extension\Generic\GenericExtensionOutput;
use PHPUnit\Framework\TestCase;

class GenericExtensionTest extends TestCase
{
    public function testInput()
    {
        $input = new GenericExtensionInput('unknown', ['a' => 'b']);
        self::assertSame(['a' => 'b'], $input->getInput());
        $input->setInput('boo');
        self::assertSame('boo', $input->getInput());
    }

    public function testOutput()
    {
        $response = new ExtensionResponse('unknown');
        $output = new GenericExtensionOutput($response);
        self::assertSame('unknown', $output->getIdentifier());
        self::assertSame($response, $output->getResponse());
    }
}

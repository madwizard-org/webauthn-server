<?php


namespace Extension;

use MadWizard\WebAuthn\Extension\UnknownExtensionInput;
use MadWizard\WebAuthn\Extension\UnknownExtensionOutput;
use PHPUnit\Framework\TestCase;

class UnknownExtensionTest extends TestCase
{
    public function testInput()
    {
        $input = new UnknownExtensionInput('unknown', ['a' => 'b']);
        $this->assertSame(['a' => 'b'], $input->getInput());
        $input->setInput('boo');
        $this->assertSame('boo', $input->getInput());
    }

    public function testOutput()
    {
        $output = new UnknownExtensionOutput('unknown', ['a' => 'b']);
        $this->assertSame(['a' => 'b'], $output->getOutput());
        $output->setInput('boo');
        $this->assertSame('boo', $output->getOutput());
    }
}

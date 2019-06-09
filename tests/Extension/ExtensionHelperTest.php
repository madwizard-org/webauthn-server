<?php

namespace MadWizard\WebAuthn\Tests\Extension;

use MadWizard\WebAuthn\Extension\ExtensionHelper;
use PHPUnit\Framework\TestCase;

class ExtensionHelperTest extends TestCase
{
    public function testValidExtensionIdentifier()
    {
        $this->assertTrue(ExtensionHelper::validExtensionIdentifier('testExtension'));
        $this->assertTrue(ExtensionHelper::validExtensionIdentifier('myCompany_extension_01'));
        $this->assertTrue(ExtensionHelper::validExtensionIdentifier("singlequote'allowed"));
        $this->assertTrue(ExtensionHelper::validExtensionIdentifier('identifierhasmaximum32characters'));

        $this->assertFalse(ExtensionHelper::validExtensionIdentifier('bachslash\\notallowed'));
        $this->assertFalse(ExtensionHelper::validExtensionIdentifier('doublequote"notallowed'));
        $this->assertFalse(ExtensionHelper::validExtensionIdentifier('whitespace not allowed'));
        $this->assertFalse(ExtensionHelper::validExtensionIdentifier('control\x05notallowed'));
        $this->assertFalse(ExtensionHelper::validExtensionIdentifier('33characterstoomuchforidentifiers'));
    }
}

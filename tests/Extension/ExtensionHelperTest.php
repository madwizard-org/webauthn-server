<?php

namespace MadWizard\WebAuthn\Tests\Extension;

use MadWizard\WebAuthn\Extension\ExtensionHelper;
use PHPUnit\Framework\TestCase;

class ExtensionHelperTest extends TestCase
{
    public function testValidExtensionIdentifier()
    {
        self::assertTrue(ExtensionHelper::validExtensionIdentifier('testExtension'));
        self::assertTrue(ExtensionHelper::validExtensionIdentifier('myCompany_extension_01'));
        self::assertTrue(ExtensionHelper::validExtensionIdentifier("singlequote'allowed"));
        self::assertTrue(ExtensionHelper::validExtensionIdentifier('identifierhasmaximum32characters'));

        self::assertFalse(ExtensionHelper::validExtensionIdentifier('bachslash\\notallowed'));
        self::assertFalse(ExtensionHelper::validExtensionIdentifier('doublequote"notallowed'));
        self::assertFalse(ExtensionHelper::validExtensionIdentifier('whitespace not allowed'));
        self::assertFalse(ExtensionHelper::validExtensionIdentifier('control\x05notallowed'));
        self::assertFalse(ExtensionHelper::validExtensionIdentifier('33characterstoomuchforidentifiers'));
    }
}

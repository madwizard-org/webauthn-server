<?php

namespace MadWizard\WebAuthn\Tests\Metadata\Source;

use MadWizard\WebAuthn\Exception\UnexpectedValueException;
use MadWizard\WebAuthn\Metadata\Provider\Apple\AppleDevicesProvider;
use MadWizard\WebAuthn\Metadata\Source\BundledSource;
use PHPUnit\Framework\TestCase;

class BundledSourceTest extends TestCase
{
    public function testEmpty()
    {
        $empty = new BundledSource([]);
        self::assertEmpty($empty->getEnableSets());
        self::assertEmpty($empty->createProviders());
    }

    public function testInvalid()
    {
        $this->expectException(UnexpectedValueException::class);
        new BundledSource(['xyz']);
    }

    public function testInvalidSet()
    {
        $this->expectException(UnexpectedValueException::class);
        new BundledSource(['@xyz']);
    }

    public function testEmptyName()
    {
        $this->expectException(UnexpectedValueException::class);
        new BundledSource(['']);
    }

    public function testDefault()
    {
        $default = new BundledSource();
        $providers = $default->createProviders();
        $providers = array_map('get_class', $providers);
        self::assertContains(AppleDevicesProvider::class, $providers);
    }

    public function testExplicit()
    {
        $default = new BundledSource(['apple']);
        $providers = $default->createProviders();
        $providers = array_map('get_class', $providers);
        self::assertContains(AppleDevicesProvider::class, $providers);
    }

    public function testDeleteSets()
    {
        $default = new BundledSource(['@all']);
        $providers = $default->createProviders();
        $providers = array_map('get_class', $providers);
        self::assertContains(AppleDevicesProvider::class, $providers);

        $default = new BundledSource(['@all', '-apple']);
        $providers = $default->createProviders();
        $providers = array_map('get_class', $providers);
        self::assertNotContains(AppleDevicesProvider::class, $providers);
    }
}

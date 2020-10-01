<?php

namespace MadWizard\WebAuthn\Tests\Extension\Appid;

use MadWizard\WebAuthn\Exception\ExtensionException;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Extension\AppId\AppIdExtension;
use MadWizard\WebAuthn\Extension\AppId\AppIdExtensionInput;
use MadWizard\WebAuthn\Extension\AppId\AppIdExtensionOutput;
use MadWizard\WebAuthn\Extension\ExtensionInputInterface;
use MadWizard\WebAuthn\Extension\ExtensionInterface;
use MadWizard\WebAuthn\Extension\ExtensionOutputInterface;
use MadWizard\WebAuthn\Extension\ExtensionProcessingContext;
use MadWizard\WebAuthn\Extension\ExtensionResponse;
use PHPUnit\Framework\TestCase;

class AppIdExtensionTest extends TestCase
{
    public function testInput()
    {
        $input = new AppIdExtensionInput('https://u2f.example.com');
        self::assertSame('https://u2f.example.com', $input->getAppId());
        self::assertSame('https://u2f.example.com', $input->getInput());
        self::assertSame('appid', $input->getIdentifier());
    }

    public function testSerialize()
    {
        $input = new AppIdExtensionInput('https://u2f.example.com');
        $input = unserialize(serialize($input));
        self::assertSame('https://u2f.example.com', $input->getAppId());
        self::assertSame('https://u2f.example.com', $input->getInput());
        self::assertSame('appid', $input->getIdentifier());
    }

    public function testOutput()
    {
        $output = new AppIdExtensionOutput(true);
        self::assertTrue($output->getAppIdUsed());
        self::assertSame('appid', $output->getIdentifier());
    }

    public function testParsing()
    {
        $response = new ExtensionResponse('appid');
        $response->setClientExtensionOutput(false);
        $ext = new AppIdExtension();
        $output = $ext->parseResponse($response);
        self::assertInstanceOf(AppIdExtensionOutput::class, $output);
        assert($output instanceof AppIdExtensionOutput);
        self::assertFalse($output->getAppIdUsed());
    }

    public function testInvalidParsing()
    {
        $response = new ExtensionResponse('appid');
        $response->setClientExtensionOutput('unexpected-string');
        $ext = new AppIdExtension();
        $this->expectException(ParseException::class);
        $this->expectExceptionMessageMatches('~expecting boolean~i');
        $ext->parseResponse($response);
    }

    public function testProcess()
    {
        $ext = new AppIdExtension();
        $input = new AppIdExtensionInput('https://u2f.example.com');

        $output = new AppIdExtensionOutput(false);
        $context = $this->createContext();
        $ext->processExtension($input, $output, $context);
        self::assertNull($context->getOverruledRpId());

        $output = new AppIdExtensionOutput(true);
        $context = $this->createContext();
        $ext->processExtension($input, $output, $context);
        self::assertSame('https://u2f.example.com', $context->getOverruledRpId());
    }

    public function testWrongInput()
    {
        $ext = new AppIdExtension();
        $context = $this->createContext();
        $this->expectException(ExtensionException::class);
        $this->expectExceptionMessageMatches('~AppIdExtensionInput~i');
        $ext->processExtension($this->createMock(ExtensionInputInterface::class), new AppIdExtensionOutput(true), $context);
    }

    public function testWrongOutput()
    {
        $ext = new AppIdExtension();
        $context = $this->createContext();
        $this->expectException(ExtensionException::class);
        $this->expectExceptionMessageMatches('~AppIdExtensionOutput~i');
        $ext->processExtension(new AppIdExtensionInput('https://u2f.example.com'), $this->createMock(ExtensionOutputInterface::class), $context);
    }

    private function createContext(): ExtensionProcessingContext
    {
        return new ExtensionProcessingContext(ExtensionInterface::OPERATION_AUTHENTICATION);
    }
}

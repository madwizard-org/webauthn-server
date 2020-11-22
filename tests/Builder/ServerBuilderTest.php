<?php

namespace MadWizard\WebAuthn\Tests\Builder;

use MadWizard\WebAuthn\Builder\ServerBuilder;
use MadWizard\WebAuthn\Config\RelyingParty;
use MadWizard\WebAuthn\Credential\CredentialStoreInterface;
use PHPStan\Testing\TestCase;
use PHPUnit\Framework\MockObject\MockObject;

/**
 * @covers \MadWizard\WebAuthn\Builder\ServerBuilder
 */
class ServerBuilderTest extends TestCase
{
    /**
     * @var ServerBuilder
     */
    private $builder;

    /**
     * @var RelyingParty
     */
    private $rp;

    /**
     * @var CredentialStoreInterface|MockObject
     */
    private $store;

    protected function setUp(): void
    {
        $this->builder = new ServerBuilder();
        $this->rp = new RelyingParty('example', 'https://example.com');
        $this->store = $this->createMock(CredentialStoreInterface::class);
    }

    public function testMinimal()
    {
        $this->builder
            ->setRelyingParty($this->rp)
            ->setCredentialStore($this->store);

        $this->builder->build();
        self::assertTrue(true);
    }
}

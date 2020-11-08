<?php

namespace MadWizard\WebAuthn\Extension;

final class ExtensionProcessingContext
{
    /**
     * @var string
     */
    private $operation;

    /**
     * @var string|null
     */
    private $overruledRpId;

    /**
     * @var array<string, ExtensionOutputInterface>
     */
    private $outputs = [];

    public function __construct(string $operation)
    {
        $this->operation = $operation;
    }

    public function getOperation(): string
    {
        return $this->operation;
    }

    public function getOverruledRpId(): ?string
    {
        return $this->overruledRpId;
    }

    public function setOverruledRpId(?string $overruledRpId): void
    {
        $this->overruledRpId = $overruledRpId;
    }

    public function addOutput(ExtensionOutputInterface $output): void
    {
        $this->outputs[$output->getIdentifier()] = $output;
    }

//    public function getOutput(string $identifier)
//    {
//        $output = $this->outputs[$identifier] ?? null;
//
//    }
}

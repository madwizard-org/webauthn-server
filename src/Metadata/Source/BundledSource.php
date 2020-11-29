<?php

namespace MadWizard\WebAuthn\Metadata\Source;

use MadWizard\WebAuthn\Metadata\Provider\Apple\AppleDevicesProvider;
use MadWizard\WebAuthn\Metadata\Provider\MetadataProviderInterface;
use UnexpectedValueException;

final class BundledSource implements MetadataSourceInterface
{
    private const SETS =
        [
            'apple' => false,
            // 'yubico-u2f' => true,
        ];

    /**
     * @var string[]
     * @phpstan-var array<string, class-string>
     */
    private const PROVIDERS = [
        'apple' => AppleDevicesProvider::class,
    ];

    /**
     * @var array<string, bool>
     */
    private $enabledSets;

    public function __construct(array $sets = ['@all'])
    {
        $this->enabledSets = self::SETS;
        foreach ($sets as $set) {
            if ($set === '') {
                throw new UnexpectedValueException('Empty set name');
            }

            if ($set === '@all') {
                $this->enabledSets = array_fill_keys(array_keys(self::SETS), true);
            } else {
                $add = true;
                if ($set[0] === '-') {
                    $set = substr($set, 1);
                    $add = false;
                }

                if (!isset(self::SETS[$set])) {
                    throw new UnexpectedValueException(sprintf("Invalid set name '%s'.", $set));
                }
                if ($add) {
                    $this->enabledSets[$set] = true;
                } elseif (isset($this->enabledSets[$set])) {
                    $this->enabledSets[$set] = false;
                }
            }
        }
    }

    public function getEnableSets(): array
    {
        return array_keys(array_filter($this->enabledSets, static function ($value) { return $value; }));
    }

    /**
     * @return MetadataProviderInterface[]
     */
    public function createProviders(): array
    {
        $providers = [];
        foreach ($this->enabledSets as $type => $enabled) {
            if ($enabled) {
                $className = self::PROVIDERS[$type];
                $providers[] = new $className();
            }
        }
        return $providers;
    }
}

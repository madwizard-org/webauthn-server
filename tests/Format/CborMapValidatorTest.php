<?php

namespace MadWizard\WebAuthn\Tests\Format;

use MadWizard\WebAuthn\Format\CborMap;
use MadWizard\WebAuthn\Format\DataValidator;

class CborMapValidatorTest extends AbstractDataValidatorTest
{
    protected function check(array $data, array $types, bool $complete = true): void
    {
        DataValidator::checkMap(CborMap::fromArray($data), $types, $complete);
    }
}

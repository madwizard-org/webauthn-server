<?php

namespace MadWizard\WebAuthn\Tests\Format;

use MadWizard\WebAuthn\Format\DataValidator;

class ArrayValidatorTest extends AbstractDataValidatorTest
{
    protected function check(array $data, array $types, bool $complete = true): void
    {
        DataValidator::checkArray($data, $types, $complete);
    }
}

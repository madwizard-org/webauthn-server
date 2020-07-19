<?php

namespace MadWizard\WebAuthn\Builder;

use MadWizard\WebAuthn\Policy\Policy;

interface PolicyCallbackInterface
{
    /**
     * @return void
     */
    public function __invoke(Policy $policy);
}

<?php

namespace MadWizard\WebAuthn\Tests\Helper;

use MadWizard\WebAuthn\Pki\X509Certificate;

class CertHelper
{
    /**
     * @return string[]
     */
    public static function pemList(X509Certificate ...$certs): array
    {
        return array_map(static function (X509Certificate $c) {
            return $c->asPem();
        }, $certs);
    }
}

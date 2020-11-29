<?php

namespace MadWizard\WebAuthn\Util;

use MadWizard\WebAuthn\Exception\NotAvailableException;

final class BundledData
{
    public static function getContents(string $path): string
    {
        $content = file_get_contents(self::getPath($path));
        if ($content === false) {
            throw new NotAvailableException(sprintf("Missing bundled data path '%s'.", $path));
        }
        return $content;
    }

    private static function getPath(string $path): string
    {
        return dirname(__DIR__, 2) . '/data/' . $path;
    }
}

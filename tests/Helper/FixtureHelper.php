<?php


namespace MadWizard\WebAuthn\Tests\Helper;

use Exception;
use function file_exists;
use function file_get_contents;

class FixtureHelper
{
    public static function getFixture(string $path) : string
    {
        $path = dirname(__DIR__) . '/fixtures/' . $path;
        if (!file_exists($path)) {
            throw new Exception(sprintf('Cannot find fixture %s.', $path));
        }

        return $path;
    }

    public static function getFixtureContent(string $path) : string
    {
        $content = file_get_contents(self::getFixture($path));
        if ($content === false) {
            throw new Exception(sprintf('Failed to load file contents from %s.', $file));
        }
        return $content;
    }
}

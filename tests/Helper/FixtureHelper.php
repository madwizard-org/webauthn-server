<?php


namespace MadWizard\WebAuthn\Tests\Helper;

use const JSON_ERROR_NONE;
use Exception;
use function file_exists;
use function file_get_contents;
use function json_last_error;

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
            throw new Exception(sprintf('Failed to load file contents from %s.', $path));
        }
        return $content;
    }

    public static function getJsonFixture(string $path)
    {
        $content = self::getFixtureContent($path);
        $data = json_decode($content, true);
        if ($data === null && json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception(sprintf('Failed to JSON parse file contents from %s.', $path));
        }
        return $data;
    }
}

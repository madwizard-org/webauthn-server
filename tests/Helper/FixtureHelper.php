<?php

namespace MadWizard\WebAuthn\Tests\Helper;

use Exception;
use MadWizard\WebAuthn\Attestation\AttestationObject;
use MadWizard\WebAuthn\Format\ByteBuffer;
use function file_exists;
use function file_get_contents;
use function json_last_error;
use const JSON_ERROR_NONE;

class FixtureHelper
{
    public static function getFixture(string $path): string
    {
        $path = dirname(__DIR__) . '/fixtures/' . $path;
        if (!file_exists($path)) {
            throw new Exception(sprintf('Cannot find fixture %s.', $path));
        }

        return $path;
    }

    public static function getFixtureContent(string $path): string
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

    public static function getTestObject(string $key): AttestationObject
    {
        $statements = self::getJsonFixture('Statement/statements.json');
        return AttestationObject::parse(ByteBuffer::fromBase64Url($statements[$key]));
    }

    public static function getTestPlain(string $key)
    {
        $data = self::getJsonFixture('Statement/statements.json');
        return $data[$key];
    }

    public static function getFidoTestObject(string $key): AttestationObject
    {
        $data = self::getJsonFixture('fido2-helpers/attestation.json');
        $attestationObject = $data[$key]['response']['attestationObject'];
        return AttestationObject::parse(ByteBuffer::fromBase64Url($attestationObject));
    }

    public static function getFidoTestPlain(string $key)
    {
        $data = self::getJsonFixture('fido2-helpers/attestation.json');
        return $data[$key];
    }
}

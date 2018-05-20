<?php


namespace MadWizard\WebAuthn\Dom;

use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Format\Base64UrlEncoding;
use MadWizard\WebAuthn\Format\ByteBuffer;

abstract class AbstractDictionary implements DictionaryInterface
{
    protected static function arrayToJSON(array $map) : array
    {
        $converted = [];
        foreach ($map as $key => $value) {
            if ($value instanceof ByteBuffer) {
                // There is no direct way to store a ByteBuffer in JSON string easily.
                // Encode the data using base64
                $converted['$buffer$' . $key] = Base64UrlEncoding::encode($value->getBinaryString());
            } elseif ($value instanceof DictionaryInterface) {
                $converted[$key] = $value->getJSONData();
            } elseif (\is_scalar($key)) {
                $converted[$key] = $value;
            } else {
                throw new WebAuthnException('Cannot convert this data to JSON format');
            }
        }

        return $converted;
    }

    public function getJSONData() : array
    {
        return self::arrayToJSON($this->getAsArray());
    }

    abstract protected function getAsArray() : array;
}

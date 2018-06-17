<?php


namespace MadWizard\WebAuthn\Dom;

use MadWizard\WebAuthn\Json\JsonConverter;

abstract class AbstractDictionary implements DictionaryInterface
{
    abstract public function getAsArray() : array;

    public function getJsonData(int $encodingOptions = JsonConverter::ENCODE_PREFIX) : array
    {
        return JsonConverter::encodeDictionary($this, $encodingOptions);
    }
}

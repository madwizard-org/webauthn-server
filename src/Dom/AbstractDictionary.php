<?php


namespace MadWizard\WebAuthn\Dom;

use MadWizard\WebAuthn\Json\JsonConverter;

abstract class AbstractDictionary implements DictionaryInterface
{
    abstract public function getAsArray() : array;

    public function getJsonData() : array
    {
        return JsonConverter::encodeDictionary($this);
    }
}

<?php


namespace MadWizard\WebAuthn\Dom;

abstract class AbstractDictionary implements DictionaryInterface
{
    abstract public function getAsArray() : array;
}

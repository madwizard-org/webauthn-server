<?php


namespace MadWizard\WebAuthn\Remote;

use Serializable;

class FileContents implements Serializable
{
    private $data;

    private $contentType;

    public function __construct(string $data, string $contentType)
    {
        $this->data = $data;
        $this->contentType = $contentType;
    }

    /**
     * @return string
     */
    public function getData(): string
    {
        return $this->data;
    }

    /**
     * @return string
     */
    public function getContentType(): string
    {
        return $this->contentType;
    }

    public function serialize()
    {
        return \serialize([$this->contentType, $this->data]);
    }

    public function unserialize($serialized)
    {
        [$this->contentType, $this->data] = \unserialize($serialized);
    }
}

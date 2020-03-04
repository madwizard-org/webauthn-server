<?php

namespace MadWizard\WebAuthn\Remote;

interface DownloaderInterface
{
    public function downloadFile(string $uri): FileContents;
}

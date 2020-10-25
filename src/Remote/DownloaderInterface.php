<?php

namespace MadWizard\WebAuthn\Remote;

use MadWizard\WebAuthn\Exception\RemoteException;

interface DownloaderInterface
{
    /**
     * @throws RemoteException
     */
    public function downloadFile(string $uri): FileContents;
}

<?php

namespace MadWizard\WebAuthn\Attestation\Android;

use MadWizard\WebAuthn\Format\ByteBuffer;

interface AndroidExtensionParserInterface
{
    /**
     * @param ByteBuffer $data The raw value of the octet string inside the X509 extension, that is the actual data bytes
     *                         from the extension's octet-string, representing an ASN.1 sequence.
     */
    public function parseAttestationExtension(ByteBuffer $data): AndroidAttestationExtension;
}

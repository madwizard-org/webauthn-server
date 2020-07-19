<?php

namespace MadWizard\WebAuthn\Attestation\Fido;

use Exception;
use MadWizard\WebAuthn\Attestation\Identifier\Aaguid;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Exception\VerificationException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Pki\CertificateDetailsInterface;
use Sop\ASN1\Type\UnspecifiedType;

final class FidoAaguidExtension
{
    private const OID_FIDO_GEN_CE_AAGUID = '1.3.6.1.4.1.45724.1.1.4';

    public static function checkAaguidExtension(CertificateDetailsInterface $cert, Aaguid $validAaguid): void
    {
        $aaguid = self::getFidoAaguidExtensionValue($cert);

        if ($aaguid === null) {
            return;
        }

        if (!$validAaguid->equals($aaguid)) {
            throw new VerificationException('AAGUID in certificate extension does not match the AAGUID in the authenticator data.');
        }
    }

    private static function getFidoAaguidExtensionValue(CertificateDetailsInterface $cert): ?Aaguid
    {
        $extension = $cert->getExtensionData(self::OID_FIDO_GEN_CE_AAGUID);
        if ($extension === null) {
            return null;
        }

        if ($extension->isCritical()) {
            throw new VerificationException('FIDO AAGUID extension must not be critical.');
        }

        try {
            $rawAaguid = UnspecifiedType::fromDER($extension->getValue()->getBinaryString())->asOctetString()->string();
            return new Aaguid(new ByteBuffer($rawAaguid));
        } catch (Exception $e) {
            throw new ParseException('Failed to parse AAGUID extension', 0, $e);
        }
    }
}

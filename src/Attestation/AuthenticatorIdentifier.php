<?php


namespace MadWizard\WebAuthn\Attestation;

use MadWizard\WebAuthn\Pki\CertificateParser;

class AuthenticatorIdentifier
{
    public const TYPE_AAGUID = 'aaguid';

    public const TYPE_AAID = 'aaid';

    public const TYPE_PUBLICKEYID = 'publickeyid';

    /**
     * @var string
     */
    private $id;

    /**
     * @var string
     */
    private $type;

    public function __construct(string $id, string $type)
    {
        $this->id = $id;
        $this->type = $type;
    }

    /**
     * @return string
     */
    public function getId(): string
    {
        return $this->id;
    }

    /**
     * @return string
     */
    public function getType(): string
    {
        return $this->type;
    }

    public static function fromAuthenticatorData(AuthenticatorDataInterface $ad) : ?AuthenticatorIdentifier // TODO Move to other class
    {
        $aaguid = $ad->getAaguid();
        if ($aaguid !== null) {
            $hex = $aaguid->getHex() ;
            if ($hex !== '00000000000000000000000000000000') {
                return new AuthenticatorIdentifier($hex, self::TYPE_AAGUID);
            }
        }
        return null;
    }

    public static function fromPemCertificate(string $pem) : AuthenticatorIdentifier
    {
        $parser = new CertificateParser();
        $cert = $parser->parsePem($pem);
        return new AuthenticatorIdentifier($cert->getPublicKeyIdentifier(), self::TYPE_PUBLICKEYID);
    }
}

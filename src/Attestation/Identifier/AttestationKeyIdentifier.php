<?php


namespace MadWizard\WebAuthn\Attestation\Identifier;

use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Pki\CertificateParser;

class AttestationKeyIdentifier implements IdentifierInterface
{
    public const TYPE = 'publickeyid';

    /**
     * @var string
     */
    private $id;

    public function __construct(string $identifier)
    {
        if (!(strlen($identifier) === 40 && ctype_xdigit($identifier))) {
            throw new ParseException('Invalid key identifier.');
        }
        $this->id = strtolower($identifier);
    }

    public function getType(): string
    {
        return self::TYPE;
    }

    public function toString(): string
    {
        return $this->id;
    }

    public function equals(IdentifierInterface $identifier): bool
    {
        return $identifier instanceof self && $this->id === $identifier->id;
    }

    // TODO MOVE to other class
    public static function fromPemCertificate(string $pem) : IdentifierInterface
    {
        $parser = new CertificateParser();
        $cert = $parser->parsePem($pem);
        return new self($cert->getPublicKeyIdentifier());
    }
}

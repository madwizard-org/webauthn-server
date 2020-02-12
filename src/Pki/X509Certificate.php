<?php


namespace MadWizard\WebAuthn\Pki;

use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Format\SerializableTrait;
use Serializable;

class X509Certificate implements Serializable
{
    use SerializableTrait;

    private const BEGIN_CERTIFICATE = '-----BEGIN CERTIFICATE-----';

    private const END_CERTIFICATE = '-----END CERTIFICATE-----';

    /**
     * @var string
     */
    private $base64;

    private function __construct(string $base64)
    {
        $this->base64 = $base64;
    }

    public static function fromDer(string $der): self
    {
        return new self(base64_encode($der));
    }

    public static function fromPem(string $pem) : self
    {
        $start = strpos($pem, self::BEGIN_CERTIFICATE);
        $end = strpos($pem, self::END_CERTIFICATE);
        if ($start === false || $end === false) {
            throw new ParseException('Missing certificate PEM armor.');
        }
        $start += strlen(self::BEGIN_CERTIFICATE);
        $base64 = substr($pem, $start, $end - $start);
        $base64 = preg_replace('~\s+~', '', $base64);
        return self::fromBase64($base64);
    }

    public static function fromBase64(string $base64) : self
    {
        $decoded = base64_decode($base64, true);
        if ($decoded === false) {
            throw new ParseException('Invalid base64 encoding in PEM certificate.');
        }
        return new X509Certificate(base64_encode($decoded));
    }

    public function asDer(): string
    {
        $binary = base64_decode($this->base64, true);
        assert(is_string($binary));
        return $binary;
    }

    public function asPem(): string
    {
        return "-----BEGIN CERTIFICATE-----\n" .
            chunk_split($this->base64, 64, "\n") .
            "-----END CERTIFICATE-----\n";
    }

    public function __serialize(): array
    {
        return ['b' => $this->base64];
    }

    public function __unserialize(array $data): void
    {
        $this->base64 = $data['b'];
    }
}

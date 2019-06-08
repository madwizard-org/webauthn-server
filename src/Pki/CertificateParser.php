<?php



namespace MadWizard\WebAuthn\Pki;

use DateTimeImmutable;
use MadWizard\WebAuthn\Exception\ParseException;
use Sop\CryptoEncoding\PEM;
use X509\Certificate\Certificate;
use X509\CertificationPath\CertificationPath;
use X509\CertificationPath\PathValidation\PathValidationConfig;

// TODO rename more general
class CertificateParser implements CertificateParserInterface
{
    public const MAX_VALIDATION_LENGTH = 5;

    public function parsePem(string $pem): CertificateDetailsInterface
    {
        return CertificateDetails::fromPem($pem);
    }

    protected function getReferenceDate() : DateTimeImmutable
    {
        return new DateTimeImmutable();
    }

    public function validateChain(array $pems) : bool
    {
        $certificates = [];
        try {
            foreach ($pems as $pem) {
                $certificates[] = Certificate::fromPEM(PEM::fromString($pem));
            }
        } catch (\Exception $e) {
            throw new ParseException('Failed to parse PEM certificate in chain.', 0, $e);
        }

        $path = new CertificationPath(...$certificates);
        $config = new PathValidationConfig($this->getReferenceDate(), self::MAX_VALIDATION_LENGTH);
        try {
            $path->validate($config);
            return true;
        } catch (\Exception $e) {
            return false;
        }
    }
}

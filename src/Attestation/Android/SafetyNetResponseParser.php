<?php


namespace MadWizard\WebAuthn\Attestation\Android;

use JWX\JWK\Asymmetric\PublicKeyJWK;
use JWX\JWT\JWT;
use JWX\JWT\ValidationContext;
use MadWizard\WebAuthn\Crypto\Der;
use MadWizard\WebAuthn\Exception\ParseException;
use Sop\CryptoEncoding\PEM;
use X509\Certificate\Certificate;
use function is_float;

class SafetyNetResponseParser implements SafetyNetResponseParserInterface
{
    public function parse(string $response): SafetyNetResponseInterface
    {
        try {
            $jwt = new JWT($response);
            if (!$jwt->header()->hasX509CertificateChain()) {
                throw new ParseException('SafetyNet response does not include x5c certificates.');
            }
            $x5c = $jwt->header()->X509CertificateChain()->value();
            if (count($x5c) === 0) {
                throw new ParseException('SafetyNet response has empty x5c certificate chain.');
            }
            $x5c = array_map(function ($x) {
                $x = base64_decode($x);
                if ($x === false) {
                    throw new ParseException('x509 does not have a valid base64 encoding.');
                }
                return Der::pem('CERTIFICATE', $x);
            }, $x5c);

            $cert = Certificate::fromPEM(PEM::fromString($x5c[0]))->tbsCertificate();
            $key = PublicKeyJWK::fromPublicKeyInfo($cert->subjectPublicKeyInfo());

            $context = ValidationContext::fromJWK($key); // TODO: TEST: no encryption used -> error

            $claims = $jwt->claims($context);

            $nonce = $claims->get('nonce')->value();
            if (!\is_string($nonce)) {
                throw new ParseException('Expecting nonce to be a string.');
            }

            $ctsProfileMatch = $claims->get('ctsProfileMatch')->value();
            if (!\is_bool($ctsProfileMatch)) {
                throw new ParseException('Expecting ctsProfileMatch to be a boolean.');
            }

            $timetampMs = $claims->get('timestampMs')->value();
            if (!is_int($timetampMs) && !is_float($timetampMs)) {
                throw new ParseException('Expecting timeStampMs to be a number.');
            }

            return new SafetyNetResponse($nonce, $x5c, $ctsProfileMatch, $timetampMs);
        } catch (\Exception $e) {
            throw new ParseException('Failed to parse SafetyNet response.', 0, $e);
        }
    }
}

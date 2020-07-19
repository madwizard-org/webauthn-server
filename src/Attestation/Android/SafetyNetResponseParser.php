<?php

namespace MadWizard\WebAuthn\Attestation\Android;

use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Pki\Jwt\Jwt;
use MadWizard\WebAuthn\Pki\Jwt\JwtInterface;
use MadWizard\WebAuthn\Pki\Jwt\JwtValidator;
use MadWizard\WebAuthn\Pki\Jwt\ValidationContext;
use MadWizard\WebAuthn\Pki\Jwt\X5cParameterReader;
use function is_float;

final class SafetyNetResponseParser implements SafetyNetResponseParserInterface
{
    public function parse(string $response): SafetyNetResponseInterface
    {
        try {
            $jwt = new Jwt($response);

            $validator = new JwtValidator();

            $x5cParam = X5cParameterReader::getX5cParameter($jwt);

            if ($x5cParam === null) {
                throw new ParseException('SafetyNet response does not include x5c certificates.');
            }

            // NOTE: the chain itself is not validated here (the specs do not tell how other than to use metadata, which
            // is done in later step when enabled.

            $context = new ValidationContext(JwtInterface::ES_AND_RSA, $x5cParam->getCoseKey());

            $claims = $validator->validate($jwt, $context);

            $nonce = $claims['nonce'] ?? null;
            if (!\is_string($nonce)) {
                throw new ParseException('Expecting nonce to be a string.');
            }

            $ctsProfileMatch = $claims['ctsProfileMatch'] ?? null;
            if (!\is_bool($ctsProfileMatch)) {
                throw new ParseException('Expecting ctsProfileMatch to be a boolean.');
            }

            $timetampMs = $claims['timestampMs'] ?? null;
            if (!is_int($timetampMs) && !is_float($timetampMs)) {
                throw new ParseException('Expecting timeStampMs to be a number.');
            }

            return new SafetyNetResponse($nonce, $x5cParam->getCertificates(), $ctsProfileMatch, $timetampMs);
        } catch (\Exception $e) {
            throw new ParseException('Failed to parse SafetyNet response.', 0, $e);
        }
    }
}

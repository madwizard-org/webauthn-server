<?php


namespace MadWizard\WebAuthn\Pki;

use MadWizard\WebAuthn\Crypto\CoseKeyInterface;
use MadWizard\WebAuthn\Crypto\Der;
use MadWizard\WebAuthn\Crypto\Ec2Key;
use MadWizard\WebAuthn\Dom\CoseAlgorithm;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Exception\UnsupportedException;
use MadWizard\WebAuthn\Exception\VerificationException;
use MadWizard\WebAuthn\Format\Base64UrlEncoding;
use MadWizard\WebAuthn\Format\ByteBuffer;

final class JwtValidator
{
    private $allowedAlgorithms = ['ES256', 'ES384', 'ES512'];

    private const ALG_INFO =
        [
            'ES256' => ['curveName' => 'prime256v1', 'curve' => Ec2Key::CURVE_P256, 'coseAlg' => CoseAlgorithm::ES256, 'coordLen' => 32, 'sigComponentLen' => 32],
            'ES384' => ['curveName' => 'secp384r1', 'curve' => Ec2Key::CURVE_P384, 'coseAlg' => CoseAlgorithm::ES384, 'coordLen' => 48, 'sigComponentLen' => 48],
            'ES512' => ['curveName' => 'secp521r1', 'curve' => Ec2Key::CURVE_P521, 'coseAlg' => CoseAlgorithm::ES512, 'coordLen' => 66, 'sigComponentLen' => 66],
        ];

    /**
     * @var ChainValidatorInterface
     */
    private $chainValidator;

    public function __construct(ChainValidatorInterface $chainValidator)
    {
        $this->chainValidator = $chainValidator;
    }

    public function validate(string $token, X509Certificate $rootKey): array
    {
        $parts = explode('.', $token);
        [$headerJson, $bodyJson, $signature] = $this->decodeToken($token);

        $header = $this->jsonDecode($headerJson);
        $body = $this->jsonDecode($bodyJson);

        if (!is_array($header)) {
            throw new ParseException('Expecting header to be a json object.');
        }

        if (!is_array($body)) {
            throw new ParseException('Expecting body to be a json object.');
        }

        // TODO: validate other header items

        $alg = $this->validateAlgorithm($header);
        $key = $this->validateX5ckey($header, $alg, $rootKey);

        if ($key === null) {
            throw new VerificationException('No key available.');
        }

        $asn1Sig = $this->convertSignature($signature, $alg);
        if (!$key->verifySignature(new ByteBuffer($parts[0] . '.' . $parts[1]), new ByteBuffer($asn1Sig))) {
            throw new VerificationException('Failed to verify JWT.');
        }

        return $body;
    }

    private function decodeToken(string $token): array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new ParseException('Invalid JWT');
        }

        return [
            Base64UrlEncoding::decode($parts[0]),
            Base64UrlEncoding::decode($parts[1]),
            Base64UrlEncoding::decode($parts[2]),
            ];
    }

    private function jsonDecode(string $json): array
    {
        $decoded = json_decode($json, true);
        if ($decoded === null && json_last_error() !== JSON_ERROR_NONE) {
            throw new ParseException(sprintf('JSON parse error in JWT: %s.', json_last_error_msg()));
        }
        return $decoded;
    }

    private function convertSignature(string $signature, string $algorithm): string
    {
        $componentLen = self::ALG_INFO[$algorithm]['sigComponentLen'];
        if (strlen($signature) !== ($componentLen * 2)) {
            throw new ParseException(sprintf('Invalid signature length %d.', strlen($signature)));
        }
        $r = substr($signature, 0, $componentLen);
        $s = substr($signature, $componentLen, $componentLen);
        return  Der::sequence(Der::unsignedInteger($r) . Der::unsignedInteger($s));
    }

    private function validateX5ckey(array $header, string $algorithm, X509Certificate $rootKey): ?CoseKeyInterface
    {
        $x5c = $header['x5c'] ?? null;
        if ($x5c === null) {
            return null;
        }
        if (!is_array($x5c)) {
            throw new ParseException('Expecting array for x5c.');
        }
        /**
         * @var X509Certificate[] $chain
         */
        $chain = array_map(function ($x) {
            if (!is_string($x)) {
                throw new ParseException('Expecting array of strings for X5C');
            }
            return X509Certificate::fromBase64($x);
        }, $x5c);

        if (count($chain) === 0) {
            return null;
        }

        if (!$this->chainValidator->validateChain($rootKey, ...array_reverse($chain))) {
            throw new VerificationException('X5C chain could not be validated.');
        }

        $pkey = openssl_pkey_get_public($chain[0]->asPem());
        if (!$pkey) {
            throw new ParseException('Failed to parse X5C certificate.');
        }
        $details = openssl_pkey_get_details($pkey);
        openssl_free_key($pkey);
        if (!$details) {
            throw new ParseException('Failed to get X5C key details.');
        }

        if ($details['type'] !== OPENSSL_KEYTYPE_EC) {
            throw new UnsupportedException(sprintf('Unsupported key type %d.', $details['type']));
        }

        $algInfo = self::ALG_INFO[$algorithm];

        if ($details['ec']['curve_name'] !== $algInfo['curveName']) {
            throw new UnsupportedException(sprintf('Mismatching curve type %s', $details['ec']['curve_name']));
        }

        return new Ec2Key(new ByteBuffer($details['ec']['x']), new ByteBuffer($details['ec']['y']), $algInfo['curve'], $algInfo['coseAlg']);
    }

    private function validateAlgorithm(array $header): string
    {
        $alg = $header['alg'] ?? null;
        if (in_array($alg, $this->allowedAlgorithms, true)) {
            return $alg;
        }
        throw new VerificationException('Algorithm not allowed.');
    }
}

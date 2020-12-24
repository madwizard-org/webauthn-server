<?php

namespace MadWizard\WebAuthn\Pki\Jwt;

use MadWizard\WebAuthn\Crypto\CoseAlgorithm;
use MadWizard\WebAuthn\Crypto\CoseKeyInterface;
use MadWizard\WebAuthn\Crypto\Ec2Key;
use MadWizard\WebAuthn\Crypto\RsaKey;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Exception\UnsupportedException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Pki\X509Certificate;

final class X5cParameterReader
{
    private const ALG_INFO =
        [
            'ES256' => ['keyType' => OPENSSL_KEYTYPE_EC, 'curveName' => 'prime256v1', 'curve' => Ec2Key::CURVE_P256, 'coseAlg' => CoseAlgorithm::ES256],
            'ES384' => ['keyType' => OPENSSL_KEYTYPE_EC, 'curveName' => 'secp384r1', 'curve' => Ec2Key::CURVE_P384, 'coseAlg' => CoseAlgorithm::ES384],
            'ES512' => ['keyType' => OPENSSL_KEYTYPE_EC, 'curveName' => 'secp521r1', 'curve' => Ec2Key::CURVE_P521, 'coseAlg' => CoseAlgorithm::ES512],
            'RS256' => ['keyType' => OPENSSL_KEYTYPE_RSA, 'coseAlg' => CoseAlgorithm::RS256],
            'RS384' => ['keyType' => OPENSSL_KEYTYPE_RSA, 'coseAlg' => CoseAlgorithm::RS256],
            'RS512' => ['keyType' => OPENSSL_KEYTYPE_RSA, 'coseAlg' => CoseAlgorithm::RS512],
        ];

    public static function getX5cParameter(JwtInterface $token): ?X5cParameter
    {
        $header = $token->getHeader();

        $chain = self::extractChain($header);
        if ($chain === null) {
            return null;
        }

        $alg = $header['alg'] ?? null;
        if (!is_string($alg) || !isset(self::ALG_INFO[$alg])) {
            throw new UnsupportedException(sprintf('Unsupported algorithm %s.', is_string($alg) ? $alg : '?'));
        }
        // Note: chain is never empty here
        $key = self::keyFromCert($chain[0], $alg);

        return new X5cParameter($chain, $key);
    }

    /**
     * @return X509Certificate[]|null
     *
     * @throws ParseException
     */
    private static function extractChain(array $header): ?array
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
        return $chain;
    }

    private static function keyFromCert(X509Certificate $cert, string $algorithm): CoseKeyInterface
    {
        $pkey = openssl_pkey_get_public($cert->asPem());
        if ($pkey === false) {
            throw new ParseException('Failed to parse X5C certificate.');
        }
        $details = openssl_pkey_get_details($pkey);
        openssl_free_key($pkey);
        if ($details === false) {
            throw new ParseException('Failed to get X5C key details.');
        }

        $algInfo = self::ALG_INFO[$algorithm];

        $type = $details['type'];
        if ($type !== $algInfo['keyType']) {
            throw new UnsupportedException(sprintf('Unsupported key type %d.', $details['type']));
        }

        if ($type === OPENSSL_KEYTYPE_EC) {
            if ($details['ec']['curve_name'] !== $algInfo['curveName']) {
                throw new UnsupportedException(sprintf('Mismatching curve type %s', $details['ec']['curve_name']));
            }
            return new Ec2Key(new ByteBuffer($details['ec']['x']), new ByteBuffer($details['ec']['y']), $algInfo['curve'], $algInfo['coseAlg']);
        }
        if ($type === OPENSSL_KEYTYPE_RSA) {
            return new RsaKey(new ByteBuffer($details['rsa']['n']), new ByteBuffer($details['rsa']['e']), $algInfo['coseAlg']);
        }

        // @phpstan-ignore-next-line
        throw new UnsupportedException('Mising type handler');
    }
}

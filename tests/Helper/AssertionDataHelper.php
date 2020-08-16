<?php

namespace MadWizard\WebAuthn\Tests\Helper;

use MadWizard\WebAuthn\Format\Base64UrlEncoding;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Server\Authentication\AuthenticationContext;
use MadWizard\WebAuthn\Web\Origin;
use RuntimeException;
use stdClass;
use function array_merge;
use function json_encode;
use function openssl_sign;
use const OPENSSL_ALGO_SHA256;

class AssertionDataHelper
{
    private $clientOptions;

    private $contextOptions;

    private $signKey;

    public const KEY_A_PRIVATE =
        "-----BEGIN EC PRIVATE KEY-----\n" .
        "MHcCAQEEICduMtuMBf2EYNDms1aQbDdcKLg6JjGwTcjzkHH+wQJ6oAoGCCqGSM49\n" .
        "AwEHoUQDQgAEPHA1+PpLIslwkuFmpwIe4cXkqDwodYg6EQ/CnvZqag3wQaHUOVoG\n" .
        "kUn8fP3dfgvFx3QRti9Gu78ffR/FF0/UkA==\n" .
        "-----END EC PRIVATE KEY-----\n";

    public const KEY_A_X = '3c7035f8fa4b22c97092e166a7021ee1c5e4a83c2875883a110fc29ef66a6a0d';

    public const KEY_A_Y = 'f041a1d4395a069149fc7cfddd7e0bc5c77411b62f46bbbf1f7d1fc5174fd490';

    public const DEFAULT_CREDENTIAL_ID = 'dGVzdF9jcmVkZW50aWFsX2lkXzEyMzQ1Njc4OTEyMzQ1Njc4OQ'; // base64url of 'test_credential_id_123456789123456789'

    public function __construct()
    {
        $credentialId = self::DEFAULT_CREDENTIAL_ID;
        $challenge = Base64UrlEncoding::encode('test_challenge_data_123456789012');

        $this->signKey = self::KEY_A_PRIVATE;

        $this->clientOptions =
            [
                'credentialId' => $credentialId,
                'challenge' => $challenge,
                'signCount' => 9,
                'flags' => 0x01,   // user present
                'rpId' => 'localhost',
                'origin' => 'http://localhost',
                'makeWrongSignature' => false,
                'makeWrongClientJson' => false,
                'removeChallenge' => false,
                'userHandle' => null,
                'tokenBinding' => null,
                'includeJsonBom' => false,
                'type' => 'webauthn.get',
            ];

        $this->contextOptions =
            [
                'challenge' => $challenge,
                'rpId' => 'localhost',
                'origin' => 'http://localhost',
                'allowedCredentials' => [$credentialId],
            ];
    }

    public function setClientOptions(array $map)
    {
        $this->clientOptions = array_merge($this->clientOptions, $map);
    }

    public function setContextOptions(array $map)
    {
        $this->contextOptions = array_merge($this->contextOptions, $map);
    }

    public function getCredentialJson(): string
    {
        $client = $this->clientOptions;

        $data = [
            'challenge' => $client['challenge'],
            'clientExtensions' => new stdClass(),
            'hashAlgorithm' => 'SHA-256',
            'origin' => $client['origin'],
            'type' => $client['type'],
        ];

        if ($client['tokenBinding']) {
            $data['tokenBinding'] = $client['tokenBinding'];
        }

        if ($client['removeChallenge']) {
            unset($data['challenge']);
        }

        $clientDataJson = json_encode(
            $data
        );

        if ($client['makeWrongClientJson']) {
            $clientDataJson = '{}{}';
        }
        if ($client['includeJsonBom']) {
            $clientDataJson = "\xEF\xBB\xBF" . $clientDataJson;
        }

        $authData = hash('sha256', $client['rpId'], true) . \chr($client['flags']) . \pack('N', $client['signCount']);

        $priv = openssl_pkey_get_private(self::KEY_A_PRIVATE);
        $signData = $authData . hash('sha256', $clientDataJson, true);
        if ($client['makeWrongSignature']) {
            $signData .= 'A';
        }

        if (!openssl_sign($signData, $signature, $priv, OPENSSL_ALGO_SHA256)) {
            throw new RuntimeException('Failed to generate signature');
        }

        return json_encode(
            [
                'rawId' => $client['credentialId'],
                'id' => $client['credentialId'],
                'type' => 'public-key',
                'response' => [
                    'clientDataJSON' => Base64UrlEncoding::encode($clientDataJson),
                    'authenticatorData' => Base64UrlEncoding::encode($authData),
                    'signature' => Base64UrlEncoding::encode($signature),
                    'userHandle' => $client['userHandle'],
                    ],
                'getClientExtensionResults' => new stdClass(),
            ]
        );
    }

    public function getContext(): AuthenticationContext
    {
        $ctx = $this->contextOptions;

        $context = new AuthenticationContext(ByteBuffer::fromBase64Url($ctx['challenge']), Origin::parse($ctx['origin']), $ctx['rpId']);

        foreach ($ctx['allowedCredentials'] as $allowed) {
            $context->addAllowCredentialId(ByteBuffer::fromBase64Url($allowed));
        }

        return $context;
    }
}

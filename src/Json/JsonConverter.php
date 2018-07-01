<?php


namespace MadWizard\WebAuthn\Json;

use MadWizard\WebAuthn\Dom\AuthenticatorAssertionResponse;
use MadWizard\WebAuthn\Dom\AuthenticatorAttestationResponse;
use MadWizard\WebAuthn\Dom\AuthenticatorResponseInterface;
use MadWizard\WebAuthn\Dom\DictionaryInterface;
use MadWizard\WebAuthn\Dom\PublicKeyCredential;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialType;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Format\Base64UrlEncoding;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Format\DataValidator;
use function is_string;

final class JsonConverter
{
    /**
     * Prefix keys of ByteBuffers with `#prefix#`
     */
    public const ENCODE_PREFIX = 1;

    /**
     * Encode ByteBuffers as base64 strings instead of base64url
     */
    public const ENCODE_BASE64 = 4;

    /**
     * @codeCoverageIgnore
     */
    private function __construct()
    {
    }

    /**
     * Parses a JSON string containing a credential returned from the JS credential API's credentials.get or
     * credentials.create. The JSOn structure matches the PublicKeyCredential interface from the WebAuthn specifications
     * closely but since it contains ArrayBuffers it cannot be directly converted to a JSON equivalent. Fields that
     * are ArrayBuffers are assumed to be base64url encoded.
     *
     * Also, the response field of the PublicKeyCredential can contain either an attestation or assertion response.
     * To determine which one to parse the $responseType parameter must be set to 'attestation' or 'assertion'.
     *
     * The required JSON structure is:
     * ```
     * {
     *   "type": "public-key",
     *   "id": "base64url encoded ArrayBuffer",
     *   "response" : << authenticator response >>,
     *   "getClientExtensionResults" : << output of credential.getClientExtensionResults() >>
     * }
     * ```
     *
     * Where the authenticator response for attestation is:
     * ```
     * {
     *   attestationObject: "base64url encoded ArrayBuffer"
     * }
     * ```
     * and for assertion response is:
     * ```
     * {
     *   authenticatorData : "base64url encoded ArrayBuffer",
     *   signature: "base64url encoded ArrayBuffer",
     *   userHandle: "base64url encoded ArrayBuffer"
     * }
     * ```
     *
     * @param string $json
     * @param string $expectedResponseType Expected type of response in the public key's response field.
     * Either 'attestation' for attestation responses or 'assertion' for assertion responses.
     * @return PublicKeyCredential
     * @throws WebAuthnException
     * @see https://www.w3.org/TR/webauthn/#publickeycredential
     */
    public static function decodeCredential(string $json, string $responseType) : PublicKeyCredential
    {
        $decoded = json_decode($json, true, 10);
        if ($decoded === false) {
            throw new WebAuthnException('Failed to decode PublicKeyCredential Json');
        }

        if (($decoded['type'] ?? PublicKeyCredentialType::PUBLIC_KEY) !== PublicKeyCredentialType::PUBLIC_KEY) {
            throw new WebAuthnException("Expecting type 'public-key'");
        }

        if (empty($decoded['id'])) {
            throw new WebAuthnException('Missing id in json data');
        }
        $id = $decoded['id'];
        if (!is_string($id)) {
            throw new WebAuthnException('Id in json data should be string');
        }

        $rawId = Base64UrlEncoding::decode($id);

        $responseData = $decoded['response'] ?? null;
        if (!is_array($responseData)) {
            throw new WebAuthnException('Expecting array data for response');
        }

        $response = self::decodeResponse($responseData, $responseType);


        // TODO: clientExtensionResults

        return new PublicKeyCredential(new ByteBuffer($rawId), $response);
    }

    public static function decodeAttestationCredential(string $json) : PublicKeyCredential
    {
        return self::decodeCredential($json, 'attestation');
    }

    public static function decodeAssertionCredential(string $json) : PublicKeyCredential
    {
        return self::decodeCredential($json, 'assertion');
    }

    private static function decodeResponse(array $response, string $responseType) : AuthenticatorResponseInterface
    {
        $clientDataJson = $response['clientDataJSON'] ?? null;

        if (!is_string($clientDataJson)) {
            throw new WebAuthnException('Expecting client data json');
        }
        $clientDataJson = Base64UrlEncoding::decode($clientDataJson);

        if ($responseType === 'assertion') {
            return self::decodeAssertionResponse($clientDataJson, $response);
        }
        if ($responseType === 'attestation') {
            return self::decodeAttestationResponse($clientDataJson, $response);
        }
        throw new WebAuthnException(sprintf('Unknown or missing type %s', $responseType));
    }

    private static function decodeAssertionResponse(string $clientDataJson, array $response) : AuthenticatorAssertionResponse
    {
        DataValidator::checkTypes(
            $response,
            [
                'authenticatorData' => 'string',
                'signature' => 'string',
                'userHandle' => '?string',
            ],
            false
        );

        $authenticatorData = new ByteBuffer(Base64UrlEncoding::decode($response['authenticatorData']));
        $signature = new ByteBuffer(Base64UrlEncoding::decode($response['signature']));

        $userHandle = null;

        $encUserHandle = $response['userHandle'] ?? null;
        if ($encUserHandle !== null) {
            $userHandle = new ByteBuffer(Base64UrlEncoding::decode($encUserHandle));
        }

        return new AuthenticatorAssertionResponse($clientDataJson, $authenticatorData, $signature, $userHandle);
    }

    private static function decodeAttestationResponse(string $clientDataJson, array $response) : AuthenticatorAttestationResponse
    {
        DataValidator::checkTypes(
            $response,
            [
                'attestationObject' => 'string',
            ],
            false
        );

        return new AuthenticatorAttestationResponse(
            $clientDataJson,
            new ByteBuffer(Base64UrlEncoding::decode($response['attestationObject']))
        );
    }

    public static function encodeDictionary(DictionaryInterface $dictionary) : array
    {
        return self::encodeArray($dictionary->getAsArray());
    }

    private static function encodeArray(array $map) : array
    {
        $converted = [];
        foreach ($map as $key => $value) {
            if ($value instanceof ByteBuffer) {
                // There is no direct way to store a ByteBuffer in JSON string easily.
                // Encode as base46url encoded string
                $converted[$key] = Base64UrlEncoding::encode($value->getBinaryString());
            } elseif ($value instanceof DictionaryInterface) {
                $converted[$key] = self::encodeDictionary($value);
            } elseif (\is_scalar($value)) {
                $converted[$key] = $value;
            } elseif (\is_array($value)) {
                $converted[$key] = self::encodeArray($value);
            } else {
                throw new WebAuthnException('Cannot convert this data to JSON format');
            }
        }
        return $converted;
    }
}

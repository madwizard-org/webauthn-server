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
use function base64_encode;
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
     *   "clientExtensionResults" : << output of credential.getClientExtensionResults() >>
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

        if (($decoded['type'] ?? null) !== PublicKeyCredentialType::PUBLIC_KEY) {
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
            $encAuthenticatorData = $response['authenticatorData'] ?? null;

            if (!is_string($encAuthenticatorData)) {
                throw new WebAuthnException('Epecting authenticator data');
            }

            $authenticatorData = new ByteBuffer(Base64UrlEncoding::decode($encAuthenticatorData));

            $encSignature = $response['signature'] ?? null;
            if (!is_string($encSignature)) {
                throw new WebAuthnException('Missing signature');
            }

            $signature = new ByteBuffer(Base64UrlEncoding::decode($encSignature));

            $userHandle = null;

            $encUserHandle = $response['userHandle'] ?? null;
            if ($encUserHandle !== null) {
                if (!is_string($encUserHandle)) {
                    throw new WebAuthnException('expectng string');
                }

                $userHandle = new ByteBuffer(Base64UrlEncoding::decode($encUserHandle));
            }

            return new AuthenticatorAssertionResponse($clientDataJson, $authenticatorData, $signature, $userHandle);
        }
        if ($responseType === 'attestation') {
            $attestationObject = $response['attestationObject'] ?? null;
            if ($attestationObject === null) {
                throw new WebAuthnException('Missing attestation object');
            }

            return new AuthenticatorAttestationResponse(
                $clientDataJson,
                new ByteBuffer(Base64UrlEncoding::decode($attestationObject))
            );
        }
        throw new WebAuthnException(sprintf('Unknown or missing type %s', $responseType));
    }

    public static function encodeDictionary(DictionaryInterface $dictionary, int $encodeFlags = self::ENCODE_PREFIX) : array
    {
        return self::encodeArray($dictionary->getAsArray(), $encodeFlags);
    }

    private static function encodeArray(array $map, int $encodeFlags) : array
    {
        $converted = [];
        foreach ($map as $key => $value) {
            if ($value instanceof ByteBuffer) {
                // There is no direct way to store a ByteBuffer in JSON string easily.
                // Encode using the flags specified
                if (($encodeFlags & self::ENCODE_PREFIX) !== 0) {
                    $key = '$buffer$' . $key;
                }
                if (($encodeFlags & self::ENCODE_BASE64) !== 0) {
                    $converted[$key] = base64_encode($value->getBinaryString());
                } else {
                    $converted[$key] = Base64UrlEncoding::encode($value->getBinaryString());
                }
            } elseif ($value instanceof DictionaryInterface) {
                $converted[$key] = self::encodeDictionary($value);
            } elseif (\is_scalar($value)) {
                $converted[$key] = $value;
            } elseif (\is_array($value)) {
                $converted[$key] = self::encodeArray($value, $encodeFlags);
            } else {
                throw new WebAuthnException('Cannot convert this data to JSON format');
            }
        }
        return $converted;
    }
}

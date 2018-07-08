<?php


namespace MadWizard\WebAuthn\Server;

use MadWizard\WebAuthn\Attestation\AuthenticatorData;
use MadWizard\WebAuthn\Credential\CredentialStoreInterface;
use MadWizard\WebAuthn\Credential\UserCredentialInterface;
use MadWizard\WebAuthn\Crypto\COSEKey;
use MadWizard\WebAuthn\Dom\AuthenticatorAssertionResponseInterface;
use MadWizard\WebAuthn\Dom\PublicKeyCredential;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialDescriptor;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialRequestOptions;
use MadWizard\WebAuthn\Dom\UserVerificationRequirement;
use MadWizard\WebAuthn\Exception\VerificationException;
use MadWizard\WebAuthn\Format\Base64UrlEncoding;
use function hash_equals;
use function var_dump;

class AssertionVerifier extends AbstractVerifier
{
    /**
     * @var CredentialStoreInterface
     */
    private $credentialCollection;

    /**
     * @var string
     */
    private $rpId;

    // add policy
    public function __construct(CredentialStoreInterface $credentialCollection)
    {
        parent::__construct();
        $this->credentialCollection = $credentialCollection;
    }

    public function verifyAuthenticatonAssertion(PublicKeyCredential $credential, AssertionContext $context) : UserCredentialInterface
    {
        // SPEC 7.2 Verifying an authentication assertion

        $response = $credential->getResponse();
        if (!($response instanceof AuthenticatorAssertionResponseInterface)) {
            throw new VerificationException('Expecting authenticator assertion response.');
        }
        $authData = new AuthenticatorData($response->getAuthenticatorData());

        // 1. If the allowCredentials option was given when this authentication ceremony was initiated, verify that
        //    credential.id identifies one of the public key credentials that were listed in allowCredentials.
        if (!$this->checkAllowCredentials($credential, $request->getAllowCredentials())) {
            throw new VerificationException('Credential not in list of allowed credentials.');
        }

        // 2. If credential.response.userHandle is present, verify that the user identified by this value is the owner
        //    of the public key credential identified by credential.id.
        // TODO

        // 3. Using credential’s id attribute (or the corresponding rawId, if base64url encoding is inappropriate for
        // your use case), look up the corresponding credential public key.
        $accountCredential = $this->credentialCollection->findAccountCredential($credential->getBase64UrlId());
        if ($accountCredential === null) {
            throw new VerificationException('Account was not found');
        }


        //TODO: Remove BOM for json_decode (see spec)

        // 4. Let cData, aData and sig denote the value of credential’s response's clientDataJSON, authenticatorData,
        //    and signature respectively.
        // 5. Let JSONtext be the result of running UTF-8 decode on the value of cData.
        // 6. Let C, the client data claimed as used for the signature, be the result of running an
        //    implementation-specific JSON parser on JSONtext.
        $c = $response->getParsedClientData();

        // 7. Verify that the value of C.type is the string webauthn.get.
        if (($c['type'] ?? null) !== 'webauthn.get') {
            throw new VerificationException('Expecting type in clientDataJSON to be webauthn.get.');
        }

        // 8. Verify that the value of C.challenge matches the challenge that was sent to the authenticator in the
        //    PublicKeyCredentialRequestOptions passed to the get() call.
        if (($c['challenge'] ?? null) !== Base64UrlEncoding::encode($request->getChallenge()->getBinaryString())) {
            throw new VerificationException('Challenge in clientDataJSON does not match the challenge in the request.');
        }

        // 9. Verify that the value of C.origin matches the Relying Party's origin.
        $origin = $c['origin'] ?? null;
        if ($origin === null) {
            throw new VerificationException('Origin missing in clientDataJSON');
        }

        if (!$this->verifyOrigin($origin, $context->getOrigin())) {
            throw new VerificationException(sprintf("Origin '%s' does not match relying party origin.", $origin));
        }

        // 10. Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection
        //     over which the attestation was obtained. If Token Binding was used on that TLS connection, also verify
        //     that C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.

        // TODO!!

        // 11. Verify that the rpIdHash in aData is the SHA-256 hash of the RP ID expected by the Relying Party.
        if (!$this->verifyRpIdHash($authData, $request)) {
            throw new VerificationException('rpIdHash was not correct.');
        }

        // 12 and 13
        if (!$this->verifyUser($authData, $request)) {
            throw new VerificationException('User verification failed');
        }

        // 14. Verify that the values of the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData are as expected, considering the client extension input values that were given as the extensions option in the get() call. In particular, any extension identifier values in the clientExtensionResults and the extensions in authData MUST be also be present as extension identifier values in the extensions member of options, i.e., no extensions are present that were not requested. In the general case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.
        // Note: Since all extensions are OPTIONAL for both the client and the authenticator, the Relying Party MUST be prepared to handle cases where none or not all of the requested extensions were acted upon.

        // TODO: not yet supported


        // 15 and 16
        if (!$this->verifySignature($response, $accountCredential->getPublicKey())) {
            throw new VerificationException('Invalid signature');
        }

        // 17 and 18
        if (!$this->verifySignatureCounter($authData, $accountCredential)) {
            throw new VerificationException('Signature counter invalid');
        }

        // If all the above steps are successful, continue with the authentication ceremony as appropriate. Otherwise, fail the authentication ceremony.
        return $accountCredential;
    }

    /**
     * @param PublicKeyCredential $credential
     * @param PublicKeyCredentialDescriptor[]|null $allowCredentials
     * @return bool
     */
    private function checkAllowCredentials(PublicKeyCredential $credential, ?array $allowCredentials) : bool
    {
        if ($allowCredentials === null) {
            return true;
        }

        $rawId = $credential->getRawId();
        foreach ($allowCredentials as $allowCredential) {
            if ($allowCredential->getId()->equals($rawId) && $allowCredential->getType() === $credential->getType()) {
                return true;
            }
        }
        return false;
    }

    private function verifyRpIdHash(AuthenticatorData $authData, PublicKeyCredentialRequestOptions $request)
    {
        // TODO: lowercase? spec?

        $validHash = hash('sha256', $request->getRpId() ?? $this->rpId, true);

        return hash_equals($validHash, $authData->getRpIdHash()->getBinaryString());
    }

    private function verifySignature(AuthenticatorAssertionResponseInterface $response, COSEKey $publicKey) : bool
    {
        // 15. Let hash be the result of computing a hash over the cData using SHA-256.
        $clientData = $response->getClientDataJSON();
        $clientDataHash = hash('sha256', $clientData, true);

        // 16. Using the credential public key looked up in step 3, verify that sig is a valid signature over the binary concatenation of aData and hash.
        $aData = $response->getAuthenticatorData()->getBinaryString();

        $signData = $aData . $clientDataHash;

        return $publicKey->verifySignature($signData, $response->getSignature()->getBinaryString());
    }

    private function verifyUser(AuthenticatorData $authData, PublicKeyCredentialRequestOptions $request) : bool
    {
        $requestedVerification = $request->getUserVerification() ?? UserVerificationRequirement::PREFERRED;

        if ($requestedVerification === UserVerificationRequirement::REQUIRED) {
            // 12. If user verification is required for this assertion, verify that the User Verified bit of the flags
            //     in aData is set.

            return $authData->isUserVerified();
        }

        // 13. If user verification is not required for this assertion, verify that the User Present bit of the flags in aData is set.
        return $authData->isUserPresent();
    }

    private function verifySignatureCounter(AuthenticatorData $authData, UserCredentialInterface $accountCredential)
    {

        // 17. If the signature counter value adata.signCount is nonzero or the value stored in conjunction with credential’s id attribute is nonzero, then run the following sub-step:
        $counter = $authData->getSignCount();
        if ($counter === 0) {
            return true;
        }
        var_dump("Counter is $counter");


        $lastCounter = $accountCredential->getSignatureCounter();
        if ($counter > $lastCounter) {
            // 18. If the signature counter value adata.signCount is
            // -> greater than the signature counter value stored in conjunction with credential’s id attribute.
            //    Update the stored signature counter value, associated with credential’s id attribute, to be the value of adata.signCount.
            return true;
        } else {
            // -> less than or equal to the signature counter value stored in conjunction with credential’s id attribute.
            //    This is a signal that the authenticator may be cloned, i.e. at least two copies of the credential private key may exist and are being used in
            // parallel. Relying Parties should incorporate this information into their risk scoring. Whether the Relying Party updates the stored signature counter value in this case, or not, or fails the authentication ceremony or not, is Relying Party-specific.

            // TODO add policy
            return false;
        }
    }
}

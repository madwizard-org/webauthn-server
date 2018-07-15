<?php


namespace MadWizard\WebAuthn\Tests\Server;

use MadWizard\WebAuthn\Config\WebAuthnConfiguration;
use MadWizard\WebAuthn\Credential\CredentialStoreInterface;
use MadWizard\WebAuthn\Credential\UserCredentialInterface;
use MadWizard\WebAuthn\Crypto\EC2Key;
use MadWizard\WebAuthn\Dom\AuthenticatorTransport;
use MadWizard\WebAuthn\Dom\COSEAlgorithm;
use MadWizard\WebAuthn\Exception\VerificationException;
use MadWizard\WebAuthn\Format\Base64UrlEncoding;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Server\Authentication\AuthenticationOptions;
use MadWizard\WebAuthn\Server\WebAuthnServer;
use MadWizard\WebAuthn\Tests\Helper\AssertionDataHelper;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class AuthenticationTest extends TestCase
{
    /**
     * @var WebAuthnConfiguration|MockObject
     */
    private $config;

    /**
     * @var CredentialStoreInterface|MockObject
     */
    private $store;

    /**
     * @var WebAuthnServer|MockObject
     */
    private $server;

    public function testStartAuthentication()
    {
        $options = new AuthenticationOptions();
        $userCredential = $this->createCredential();
        $options->addAllowCredential($userCredential);
        $request = $this->server->startAuthentication($options);
        $clientOptions = $request->getClientOptions();
        $allowCredentials = $clientOptions->getAllowCredentials();
        $this->assertCount(1, $allowCredentials);
        $this->assertSame($userCredential->getCredentialId(), Base64UrlEncoding::encode($allowCredentials[0]->getId()->getBinaryString()));
        $this->assertContains(AuthenticatorTransport::USB, $allowCredentials[0]->getTransports());
        $this->assertNull($clientOptions->getRpId());

        $this->assertSame(
            [
                'challenge' => $request->getContext()->getChallenge()->getBase64Url(),
                'allowCredentials' =>
                    [
                        [
                            'type' => 'public-key',
                            'id' => $userCredential->getCredentialId(),
                            'transports' =>
                                [
                                    0 => 'usb',
                                    1 => 'nfc',
                                    2 => 'ble',
                                ],
                        ],
                    ],
            ],
            $clientOptions->getJsonData()
        );
    }

    public function runAuth(AssertionDataHelper $helper) : UserCredentialInterface
    {
        $credential = $this->createCredential();
        $this->store
            ->expects($this->any())
            ->method('findCredential')
            ->with($credential->getCredentialId())
            ->willReturn($credential);

        return $this->server->finishAuthentication($helper->getCredentialJson(), $helper->getContext());
    }

    public function testValidAssertion()
    {
        $helper = new AssertionDataHelper();

        $userCred = $this->runAuth($helper);
        $this->assertSame(AssertionDataHelper::DEFAULT_CREDENTIAL_ID, $userCred->getCredentialId());
        /** @var EC2Key $pubKey */
        $pubKey = $userCred->getPublicKey();

        $this->assertSame(AssertionDataHelper::KEY_A_X, $pubKey->getX()->getHex());
        $this->assertSame(AssertionDataHelper::KEY_A_Y, $pubKey->getY()->getHex());
    }

    public function testAllowedCredentials()
    {
        // SPEC 7.2.1 If the allowCredentials option was given when this authentication ceremony was initiated,
        // verify that credential.id identifies one of the public key credentials that were listed in allowCredentials.
        $helper = new AssertionDataHelper();

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessageRegExp('~not in list of allowed credentials~i');

        $helper->setContextOptions(['allowedCredentials' => [Base64UrlEncoding::encode('different credential id')]]);
        $this->runAuth($helper);
    }

//    public function testUserHandleOwner()
//    {
//        // SPEC 7.2.2 If credential.response.userHandle is present, verify that the user identified by this value is
//        // the owner of the public key credential identified by credential.id.
//        $helper = new AssertionDataHelper();
//
//        $userHandle = Base64UrlEncoding::encode('handle');
//
//        $helper->setContextOptions(['allowedCredentials' => [Base64UrlEncoding::encode('different credential id')]]);
//        $userCred = $this->runAuth($helper);
//        $this->assertSame($userHandle->getHex(), )
//    }

    public function testInvalidClientDataJSON()
    {
        // SPEC 7.2.5 JSON parse
        $helper = new AssertionDataHelper();

        $helper->setClientOptions(['makeWrongClientJson' => true]);

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessageRegExp('~failed to parse json~i');

        $this->runAuth($helper);
    }

    public function testCredentialType()
    {
        // SPEC 7.2.6 Verify that the value of C.type is the string webauthn.get.
        $helper = new AssertionDataHelper();

        $helper->setClientOptions(['type' => 'webauthn.create']);

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessageRegExp('~webauthn\.get~i');

        $this->runAuth($helper);
    }

    public function testSameChallenge()
    {
        // SPEC 7.2.8 Verify that the value of C.challenge matches the challenge that was sent to the authenticator
        // in the PublicKeyCredentialRequestOptions passed to the get() call.
        $helper = new AssertionDataHelper();

        $helper->setClientOptions(['challenge' => Base64UrlEncoding::encode('differentchallenge123456789')]);

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessageRegExp('~challenge.+does not match~i');

        $this->runAuth($helper);
    }

    public function testSameOrigin()
    {
        // SPEC 7.2.9 Verify that the value of C.origin matches the Relying Party's origin.
        $helper = new AssertionDataHelper();

        $helper->setClientOptions(['origin' => 'http://example.com']);

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessageRegExp('~origin.+does not match~i');

        $this->runAuth($helper);
    }

    public function testRpIdMatches()
    {
        // SPEC 7.2.11 Verify that the rpIdHash in aData is the SHA-256 hash of the RP ID expected by the Relying Party.
        $helper = new AssertionDataHelper();

        $helper->setClientOptions(['rpId' => 'not-localhost']);

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessageRegExp('~rpIdHash was not correct~i');

        $this->runAuth($helper);
    }

    protected function setUp()
    {
        $this->config = new WebAuthnConfiguration();
        $this->config->setRelyingPartyName('Example');
        $this->config->setRelyingPartyOrigin('https://example.com');
        $this->store = $this->createMock(CredentialStoreInterface::class);
        $this->server = new WebAuthnServer($this->config, $this->store);
    }

    private function createCredential() : UserCredentialInterface
    {
        /**
         * @var $cred UserCredentialInterface|MockObject
         */
        $cred = $this->createMock(UserCredentialInterface::class);

        $cred->expects($this->any())
            ->method('getCredentialId')
            ->willReturn(AssertionDataHelper::DEFAULT_CREDENTIAL_ID);

        $cred->expects($this->any())
            ->method('getPublicKey')
            ->willReturn(
                new EC2Key(
                    ByteBuffer::fromHex(AssertionDataHelper::KEY_A_X),
                    ByteBuffer::fromHex(AssertionDataHelper::KEY_A_Y),
                    EC2Key::CURVE_P256,
                    COSEAlgorithm::ES256
                )
            );
        $cred->expects($this->any())
            ->method('getSignatureCounter')
            ->willReturn(8);

        return $cred;
    }
}

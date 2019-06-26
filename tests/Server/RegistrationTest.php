<?php


namespace MadWizard\WebAuthn\Tests\Server;

use MadWizard\WebAuthn\Config\WebAuthnConfiguration;
use MadWizard\WebAuthn\Credential\CredentialRegistration;
use MadWizard\WebAuthn\Credential\CredentialStoreInterface;
use MadWizard\WebAuthn\Credential\UserCredentialInterface;
use MadWizard\WebAuthn\Crypto\Ec2Key;
use MadWizard\WebAuthn\Dom\CoseAlgorithm;
use MadWizard\WebAuthn\Format\Base64UrlEncoding;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Server\Registration\RegistrationContext;
use MadWizard\WebAuthn\Server\Registration\RegistrationOptions;
use MadWizard\WebAuthn\Server\UserIdentity;
use MadWizard\WebAuthn\Server\WebAuthnServer;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;
use MadWizard\WebAuthn\Web\Origin;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use function json_encode;

class RegistrationTest extends TestCase
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

    private const CREDENTIAL_ID = 'Bo-VjHOkJZy8DjnCJnIc0Oxt9QAz5upMdSJxNbd-GyAo6MNIvPBb9YsUlE0ZJaaWXtWH5FQyPS6bT_e698IirQ';

    public function testStartRegistration()
    {
        $user = new UserIdentity(ByteBuffer::fromHex('123456'), 'demo', 'Demo user');
        $options = new RegistrationOptions($user);
        $request = $this->server->startRegistration($options);

        $clientOptions = $request->getClientOptions();
        $this->assertSame('123456', $clientOptions->getUserEntity()->getId()->getHex());
        $this->assertSame('demo', $clientOptions->getUserEntity()->getName());
        $this->assertSame('Demo user', $clientOptions->getUserEntity()->getDisplayName());
        $this->assertSame('example.com', $request->getContext()->getRpId());
        $this->assertSame(64, $clientOptions->getChallenge()->getLength());
        $this->assertNull($clientOptions->getAttestation());
    }

    public function testFinishRegistration()
    {
        $json = FixtureHelper::getJsonFixture('fido2-helpers/attestation.json');

        $credential = $json['challengeResponseAttestationU2fMsgB64Url'];
        $credentialJson = json_encode($credential);



        $this->store
            ->expects($this->once())
            ->method('registerCredential')
            ->with(
                $this->callback(
                    function (CredentialRegistration $reg) {
                        return $reg->getCredentialId() === self::CREDENTIAL_ID &&
                            $reg->getUserHandle()->equals(new ByteBuffer('00112233')) &&
                            $reg->getPublicKey() instanceof Ec2Key;
                    }
            )
            );

        $challenge = new ByteBuffer(Base64UrlEncoding::decode('Vu8uDqnkwOjd83KLj6Scn2BgFNLFbGR7Kq_XJJwQnnatztUR7XIBL7K8uMPCIaQmKw1MCVQ5aazNJFk7NakgqA'));
        $context = new RegistrationContext($challenge, Origin::parse('https://localhost:8443'), 'localhost', new ByteBuffer('00112233'));
        $result = $this->server->finishRegistration($credentialJson, $context);

        $this->assertSame(self::CREDENTIAL_ID, $result->getCredentialId());
        $this->assertSame('Basic', $result->getVerificationResult()->getAttestationType());  // TODO:ugly
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
            ->willReturn('AAhH7cnPRBkcukjnc2G2GM1H5dkVs9P1q2VErhD57pkzKVjBbixdsufjXhUOfiD27D0VA-fPKUVYNGE2XYcjhihtYODQv-xEarplsa7Ix6hK13FA6uyRxMgHC3PhTbx-rbq_RMUbaJ-HoGVt-c820ifdoagkFR02Van8Vr9q67Bn6zHNDT_DNrQbtpIUqqX_Rg2p5o6F7bVO3uOJG9hUNgUb');

        $cred->expects($this->any())
            ->method('getPublicKey')
            ->willReturn(
                new Ec2Key(
                    ByteBuffer::fromHex('8d617e65c9508e64bcc5673ac82a6799da3c1446682c258c463fffdf58dfd2fa'),
                    ByteBuffer::fromHex('3e6c378b53d795c4a4dffb4199edd7862f23abaf0203b4b8911ba0569994e101'),
                    Ec2Key::CURVE_P256,
                    CoseAlgorithm::ES256
                )
            );

        return $cred;
    }
}

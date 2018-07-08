<?php


namespace MadWizard\WebAuthn\Tests\Server;

use MadWizard\WebAuthn\Config\WebAuthnConfiguration;
use MadWizard\WebAuthn\Format\Base64UrlEncoding;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Server\AttestationContext;
use MadWizard\WebAuthn\Server\Registration\RegistrationOptions;
use MadWizard\WebAuthn\Server\Registration\UserIdentity;
use MadWizard\WebAuthn\Server\WebAuthnServer;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;
use MadWizard\WebAuthn\Web\Origin;
use PHPUnit\Framework\TestCase;
use function json_encode;

class WebAuthnServerTest extends TestCase
{
    public function testStartRegistration()
    {
        $server = $this->createServer();

        $user = new UserIdentity(ByteBuffer::fromHex('123456'), 'demo', 'Demo user');
        $options = new RegistrationOptions($user);
        $request = $server->startRegistration($options);

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

        $server = $this->createServer($config);

        $config = new WebAuthnConfiguration();
        $config->setRelyingPartyName('Example');
        $config->setRelyingPartyOrigin('https://example.com');

        $challenge = new ByteBuffer(Base64UrlEncoding::decode('Vu8uDqnkwOjd83KLj6Scn2BgFNLFbGR7Kq_XJJwQnnatztUR7XIBL7K8uMPCIaQmKw1MCVQ5aazNJFk7NakgqA'));
        $context = new AttestationContext($challenge, Origin::parse('https://localhost:8443'), 'localhost');
        $result = $server->finishRegistration($credentialJson, $context);

        $this->assertSame('Bo-VjHOkJZy8DjnCJnIc0Oxt9QAz5upMdSJxNbd-GyAo6MNIvPBb9YsUlE0ZJaaWXtWH5FQyPS6bT_e698IirQ', $result->getCredentialId());
        $this->assertSame('Basic', $result->getAttestation()->getAttestation()->getAttestationType());  // TODO:ugly
    }

    private function createServer(&$config = null) : WebAuthnServer
    {
        $config = new WebAuthnConfiguration();
        $config->setRelyingPartyName('Example');
        $config->setRelyingPartyOrigin('https://example.com');

        return new WebAuthnServer($config);
    }
}

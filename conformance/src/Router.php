<?php


namespace MadWizard\WebAuthn\Conformance;

use MadWizard\WebAuthn\Config\RelyingParty;
use MadWizard\WebAuthn\Config\WebAuthnConfiguration;
use MadWizard\WebAuthn\Credential\CredentialStoreInterface;
use MadWizard\WebAuthn\Credential\UserHandle;
use MadWizard\WebAuthn\Dom\AuthenticatorSelectionCriteria;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Extension\UnknownExtensionInput;
use MadWizard\WebAuthn\Metadata\NullMetadataResolver;
use MadWizard\WebAuthn\Policy\Policy;
use MadWizard\WebAuthn\Policy\Trust\TrustDecisionManager;
use MadWizard\WebAuthn\Server\Authentication\AuthenticationOptions;
use MadWizard\WebAuthn\Server\Registration\RegistrationContext;
use MadWizard\WebAuthn\Server\Registration\RegistrationOptions;
use MadWizard\WebAuthn\Server\UserIdentity;
use MadWizard\WebAuthn\Server\WebAuthnServer;

class Router
{
    /**
     * @var WebAuthnServer
     */
    private $server;

    /**
     * @var CredentialStoreInterface
     */
    private $store;

    /**
     * @var string
     */
    private $varDir;

    /**
     * @var bool
     */
    private $debug;

    /**
     * @var int|null
     */
    private $debugIdx;

    public function __construct(string $metadataDir, string $varDir)
    {
        $this->store = new TestCredentialStore();
        $this->server = $this->createServer($metadataDir);
        $this->varDir = $varDir;
        $this->debug = true;
    }

    private function createServer(string $metadataDir) : WebAuthnServer
    {
        $rp = new RelyingParty('Test server', 'http://' . $_SERVER['HTTP_HOST']);
        $config = new WebAuthnConfiguration();
        $config->setUserPresenceRequired(false);
        $metadataResolver = new NullMetadataResolver();
        $trustDecisionManager = new TrustDecisionManager();
        $policy = new Policy($rp, $metadataResolver, $trustDecisionManager);
        return new WebAuthnServer($config, $policy, $this->store);
    }

    private function getPostJson(string $postData) : array
    {
        $json = json_decode($postData, true, 10);
        if ($json === null) {
            throw new StatusException('Invalid JSON posted');
        }

        return $json;
    }

    public function run(string $url)
    {
        try {
            $this->debugIdx = null;
            $postData = file_get_contents('php://input');
            error_log($url);
            //error_log("  In:  " . $postData);
            $response = $this->getResponse($url, $postData);
        } catch (StatusException $e) {
            $prefix = $this->debugIdx === null ? '' : ($this->debugIdx . ' ');
            $response = [500, ['status' => 'failed', 'errorMessage' => $prefix . $e->getMessage()]];
        } catch (WebAuthnException $e) {
            $prefix = $this->debugIdx === null ? '' : ($this->debugIdx . ' ');
            $response = [400, ['status' => 'failed', 'errorMessage' => $prefix . $e->getMessage() . PHP_EOL . $e->getTraceAsString()] ];
        }

        if ($response === null) {
            $response = [404, ['status' => 'failed']];
        }

        if ($this->debugIdx !== null) {
            $response[1]['_idx'] = $this->debugIdx;
        }
        //error_log(sprintf("  Out: [%d] %s", $response[0], json_encode($response[1])));

        http_response_code($response[0]);
        header('Content-Type: application/json');
        die(json_encode($response[1], JSON_PRETTY_PRINT));
    }

    private function getResponse(string $url, string $postData) :?array
    {
        $saveReq = $this->debug;
        $serDir = $this->varDir . DIRECTORY_SEPARATOR . '/ser/';

        if (preg_match('~^/test/(\d+)$~', $url, $match)) {
            $file = $serDir . $match[1];
            if (!file_exists(($file))) {
                return null;
            }
            [$session, $url, $postData] = unserialize(file_get_contents($file));
            $_SESSION = $session;
            $saveReq = false;
        }

        if ($saveReq) {
            if (!is_dir($serDir)) {
                mkdir($serDir);
            }
            $idx = (int) ($_SESSION['x'] ?? 0);
            $idx++;
            $_SESSION['x'] = $idx;
            $this->debugIdx = $idx;
            file_put_contents($serDir . $idx, \serialize([$_SESSION, $url, $postData]));
        }

        switch ($url) {
            case '/attestation/options':
                return $this->attestationOptions($postData);
            case '/attestation/result':
                return $this->attestationResult($postData);
            case '/assertion/options':
                return $this->assertionOptions($postData);
            case '/assertion/result':
                return $this->assertionResult($postData);
        }
        return null;
    }

    public function attestationOptions(string $postData) : array
    {
        $req = $this->getPostJson($postData);
        $userIdentity = new UserIdentity(
            UserHandle::fromBinary($req['username']),
            $req['username'],
            $req['displayName']
        );

        $sel = $req['authenticatorSelection'] ?? [];
        $crit = new AuthenticatorSelectionCriteria();
        if (($v = $sel['authenticatorAttachment'] ?? null) !== null) {
            $crit->setAuthenticatorAttachment($v);
        }
        if (($v = $sel['requireResidentKey'] ?? null) !== null) {
            $crit->setRequireResidentKey($v);
        }
        if (($v = $sel['userVerification'] ?? null) !== null) {
            $crit->setUserVerification($v);
        }




        $att = $req['attestation'] ?? 'none';

        $opts = new RegistrationOptions($userIdentity);

        $opts->setAttestation($att);
        $opts->setAuthenticatorSelection($crit);
        foreach ($req['extensions'] ?? [] as $identifier => $ext) {
            $opts->addExtensionInput(new UnknownExtensionInput($identifier, $ext));
        }
        $opts->setExcludeExistingCredentials(true);
        $regReq = $this->server->startRegistration($opts);



        $_SESSION['context'] = $regReq->getContext();
        return [200, array_merge(['status' => 'ok', 'errorMessage' => ''], $regReq->getClientOptionsJson())];
    }

    public function attestationResult(string $req) : array
    {
        $context = $_SESSION['context'];

        if (!($context instanceof  RegistrationContext)) {
            return [500, ['status' => 'error', 'errorMessage' => $req]];
        }
        $this->server->finishRegistration($req, $context);

        return [200, ['status' => 'ok', 'errorMessage' => '']];
    }

    public function assertionOptions(string $postData) : array
    {
        $req = $this->getPostJson($postData);

        $opts = new AuthenticationOptions();
        foreach ($req['extensions'] ?? [] as $identifier => $ext) {
            $opts->addExtensionInput(new UnknownExtensionInput($identifier, $ext));
        }

        $opts->allowUserHandle(UserHandle::fromBinary($req['username']));
        $opts->setUserVerification($req['userVerification'] ?? 'preferred');

        $regReq = $this->server->startAuthentication($opts);

        $_SESSION['context'] = $regReq->getContext();
        return [200, array_merge(['status' => 'ok', 'errorMessage' => ''], $regReq->getClientOptionsJson())];
    }

    public function assertionResult(string $req) : array
    {
        $context = $_SESSION['context'];

        $this->server->finishAuthentication($req, $context);

        return [200, ['status' => 'ok', 'errorMessage' => '']];
    }
}

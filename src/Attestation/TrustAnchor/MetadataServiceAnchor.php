<?php


namespace MadWizard\WebAuthn\Attestation\TrustAnchor;

use MadWizard\WebAuthn\Attestation\Verifier\VerificationResult;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use function in_array;

class MetadataServiceAnchor implements TrustAnchorInterface
{
    private const SUPPORTED_VERSIONS = [1, 2];

    /**
     * @var int
     */
    private $version;

    /**
     * @var string
     */
    private $cacheDir;

    /**
     * @var string|null
     */
    private $token;

    public function __construct(int $version, array $options)
    {
        if (!in_array($version, self::SUPPORTED_VERSIONS, true)) {
            throw new WebAuthnException(sprintf('Unsupported metadata service versiom %d. Supported are: %s.', $version, implode(', ', self::SUPPORTED_VERSIONS)));
        }
        $this->version = $version;

        $cacheDir = (string) ($options['cache_dir'] ?? '');
        if ($cacheDir === '') {
            throw new WebAuthnException(sprintf('Missing cache_dir option for metadata service.'));
        }

        $this->cacheDir = $cacheDir;

        if ($version === 2) {
            $token = (string) ($options['access_token'] ?? '');
            if ($token === '') {
                throw new WebAuthnException(sprintf('Metadata service version %d requires an access token. Please request a token from the FIOD alliance at https://mds2.fidoalliance.org/tokens/', $version));
            }
            $this->token = $token;
        }
    }

    public function isTrusted(VerificationResult $verificationResult): TrustStatus
    {
        // TODO: Implement isTrusted() method.
    }
}

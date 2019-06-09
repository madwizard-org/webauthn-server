<?php


namespace MadWizard\WebAuthn\Attestation\Verifier;

use MadWizard\WebAuthn\Attestation\Android\SafetyNetResponseParser;
use MadWizard\WebAuthn\Attestation\Android\SafetyNetResponseParserInterface;
use MadWizard\WebAuthn\Attestation\AttestationType;
use MadWizard\WebAuthn\Attestation\AuthenticatorData;
use MadWizard\WebAuthn\Attestation\Statement\AndroidSafetyNetAttestationStatement;
use MadWizard\WebAuthn\Attestation\Statement\AttestationStatementInterface;
use MadWizard\WebAuthn\Attestation\TrustPath\CertificateTrustPath;
use MadWizard\WebAuthn\Exception\VerificationException;
use MadWizard\WebAuthn\Pki\CertificateParser;
use MadWizard\WebAuthn\Pki\CertificateParserInterface;
use X509\Certificate\Certificate;
use function base64_encode;
use function hash_equals;
use function microtime;

class AndroidSafetyNetAttestationVerifier implements AttestationVerifierInterface
{
    private const ATTEST_HOSTNAME = 'attest.android.com';

    /**
     * @var CertificateParserInterface
     */
    private $certificateParser;

    /**
     * @var SafetyNetResponseParserInterface
     */
    private $responseParser;

    public function __construct(?CertificateParserInterface $certificateParser = null, ?SafetyNetResponseParserInterface $responseParser = null)
    {
        $this->certificateParser = $certificateParser ?? new CertificateParser();
        $this->responseParser = $responseParser ?? new SafetyNetResponseParser();
    }

    protected function getMsTimestamp() : float
    {
        return microtime(true) * 1000;
    }

    public function verify(AttestationStatementInterface $attStmt, AuthenticatorData $authenticatorData, string $clientDataHash) : VerificationResult
    {
        if (!($attStmt instanceof AndroidSafetyNetAttestationStatement)) {
            throw new VerificationException('Expecting AndroidSafetyNetAttestationStatement');
        }

        // Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
        // -> this is done in AndroidSafetyNetAttestationStatement

        // Verify that response is a valid SafetyNet response of version ver.
        $response = $this->responseParser->parse($attStmt->getResponse());

        // Verify that the nonce in the response is identical to the Base64 encoding of the SHA-256 hash of the concatenation of authenticatorData and clientDataHash.
        $expectedNonce = base64_encode(hash('sha256', $authenticatorData->getRaw()->getBinaryString() . $clientDataHash, true));

        if (!hash_equals($expectedNonce, $response->getNonce())) {
            throw new VerificationException('Nonce is invalid.');
        }

        // Let attestationCert be the attestation certificate.
        $x5c = $response->getCertificateChain();
        if (!isset($x5c[0])) {
            throw new VerificationException('No certificates in chain.');
        }
        $attCert = $x5c[0];

        // Verify that attestationCert is issued to the hostname "attest.android.com" (see SafetyNet online documentation).
        $certInfo = $this->certificateParser->parsePem($attCert);
        $cn = $certInfo->getSubjectCommonName();

        if ($cn !== self::ATTEST_HOSTNAME) {
            throw new VerificationException(sprintf('Attestation certificate should be issued to %s.', self::ATTEST_HOSTNAME));
        }

        // Verify that the ctsProfileMatch attribute in the payload of response is true.
        if (!$response->isCtsProfileMatch()) {
            throw new VerificationException('Attestation should have ctsProfileMatch set to true.');
        }

        $diff = $this->getMsTimestamp() - $response->getTimestampMs();

        if ($diff < -60e3 || $diff > 60e3) {
            throw new VerificationException('Timestamp is not within margin of one minute');
        }

        // If successful, return implementation-specific values representing attestation type Basic and attestation trust path attestationCert.
        return new VerificationResult(AttestationType::BASIC, new CertificateTrustPath($x5c));
    }
}

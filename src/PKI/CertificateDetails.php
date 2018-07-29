<?php


namespace MadWizard\WebAuthn\PKI;

use ASN1\Type\UnspecifiedType;
use Exception;
use LogicException;
use MadWizard\WebAuthn\Dom\COSEAlgorithm;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use Sop\CryptoBridge\Crypto;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA256AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\Signature\Signature;
use X509\Certificate\Certificate;
use X509\Certificate\TBSCertificate;

class CertificateDetails
{
    /**
     * @var TBSCertificate
     */
    private $cert;

    private const OID_FIDO_GEN_CE_AAGUID = '1.3.6.1.4.1.45724.1.1.4';

    private function __construct(TBSCertificate $certificate)
    {
        $this->cert = $certificate;
    }

    public static function fromPEM(string $pem) : CertificateDetails
    {
        try {
            return new self(Certificate::fromPEM(PEM::fromString($pem))->tbsCertificate());
        } catch (Exception $e) {
            throw new ParseException('Failed to parse PEM certificate.', 0, $e);
        }
    }

    public function verifySignature(string $data, string $signature, int $coseAlgorithm) : bool
    {
        $signatureAlgorithm = $this->convertCoseAlgorthm($coseAlgorithm);
        try {
            $signatureData = Signature::fromSignatureData($signature, $signatureAlgorithm);
            $key = $this->cert->subjectPublicKeyInfo();
            $crypto = Crypto::getDefault();
            return $crypto->verify($data, $signatureData, $key, $signatureAlgorithm);
        } catch (Exception $e) {
            throw new WebAuthnException('Failed to verify signature.', 0, $e);
        }
    }

    private function convertCoseAlgorthm(int $coseAlgorithm) : SignatureAlgorithmIdentifier
    {
        if ($coseAlgorithm === COSEAlgorithm::ES256) {
            return new ECDSAWithSHA256AlgorithmIdentifier();
        }

        if ($coseAlgorithm === COSEAlgorithm::RS256) {
            return new SHA256WithRSAEncryptionAlgorithmIdentifier();
        }

        throw new WebAuthnException(sprintf('Signature format %d not supported.', $coseAlgorithm));
    }

    public function getFidoAaguidExtensionValue() : ?ByteBuffer
    {
        try {
            $extension = $this->cert->extensions()->get(self::OID_FIDO_GEN_CE_AAGUID);
        } catch (LogicException $e) {
            // No extension present
            return null;
        }

        if ($extension->isCritical()) {
            throw new WebAuthnException('FIDO AAGUID extension must not be critical.');
        }

        try {
            $derEncoded = $extension->toASN1()->at(1)->asOctetString()->string();
            $rawAaguid = UnspecifiedType::fromDER($derEncoded)->asOctetString()->string();
            return new ByteBuffer($rawAaguid);
        } catch (Exception $e) {
            throw new ParseException('Failed to parse AAGUID extension', 0, $e);
        }
    }

    public function getCertificateVersion() : ?int
    {
        try {
            return $this->cert->version();
        } catch (LogicException $e) {
            return null;
        }
    }

    public function getOrganizationalUnit()
    {
        try {
            return $this->cert->subject()->firstValueOf('OU')->stringValue();
        } catch (Exception $e) {
            throw new ParseException('Failed to retrieve the oganizational unit', 0, $e);
        }
    }

    public function isCA() : ?bool
    {
        $extensions = $this->cert->extensions();

        if (!$extensions->hasBasicConstraints()) {
            return null;
        }

        return $extensions->basicConstraints()->isCA();
    }
}

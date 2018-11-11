<?php


namespace MadWizard\WebAuthn\Pki;

use ASN1\Type\UnspecifiedType;
use Exception;
use LogicException;
use MadWizard\WebAuthn\Dom\CoseAlgorithm;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use Sop\CryptoBridge\Crypto;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA256AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\Signature\Signature;
use X509\Certificate\Certificate;
use X509\Certificate\TBSCertificate;

class CertificateDetails implements CertificateDetailsInterface
{
    public const VERSION_1 = TBSCertificate::VERSION_1;

    public const VERSION_2 = TBSCertificate::VERSION_2;

    public const VERSION_3 = TBSCertificate::VERSION_3;

    /**
     * @var TBSCertificate
     */
    private $cert;

    private const OID_FIDO_GEN_CE_AAGUID = '1.3.6.1.4.1.45724.1.1.4';

    private function __construct(TBSCertificate $certificate)
    {
        $this->cert = $certificate;
    }

    public static function fromPem(string $pem) : CertificateDetails
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
        switch ($coseAlgorithm) {
            case CoseAlgorithm::ES256:
                return new ECDSAWithSHA256AlgorithmIdentifier();
            case CoseAlgorithm::ES384:
                return new ECDSAWithSHA256AlgorithmIdentifier();
            case CoseAlgorithm::ES512:
                return new ECDSAWithSHA256AlgorithmIdentifier();
            case CoseAlgorithm::RS256:
                return new SHA256WithRSAEncryptionAlgorithmIdentifier();
            case CoseAlgorithm::RS384:
                return new SHA256WithRSAEncryptionAlgorithmIdentifier();
            case CoseAlgorithm::RS512:
                return new SHA256WithRSAEncryptionAlgorithmIdentifier();
            case CoseAlgorithm::RS1:
                return new SHA1WithRSAEncryptionAlgorithmIdentifier();
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
        // NOTE: version() can throw a LogicException if no version is set, however this is never the case
        // when reading certificates. Even version 1 x509 certificates without the (optional) tagged version
        // will always default to version 1.
        return $this->cert->version();
    }

    public function getOrganizationalUnit() : string
    {
        try {
            return $this->cert->subject()->firstValueOf('OU')->stringValue();
        } catch (Exception $e) {
            throw new ParseException('Failed to retrieve the organizational unit', 0, $e);
        }
    }

    public function getSubject() : string
    {
        try {
            return $this->cert->subject()->toString();
        } catch (Exception $e) {
            throw new ParseException('Failed to retrieve subject unit', 0, $e);
        }
    }

    public function getSubjectAlternateNameDN(string $oid) : string
    {
        try {
            $attrValue = $this->cert->extensions()->subjectAlternativeName()->names()->firstDN()->firstValueOf($oid);
            return $attrValue->toASN1()->asUnspecified()->asUTF8String()->string();
        } catch (Exception $e) {
            throw new ParseException(sprintf('Failed to retrieve %s entry in directoryName in alternate name.', $oid), 0, $e);
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

    public function extendedKeyUsageContains(string $oid): bool
    {
        try {
            $extensions = $this->cert->extensions();
            if (!$extensions->hasExtendedKeyUsage()) {
                return false;
            }
            return $extensions->extendedKeyUsage()->has($oid);
        } catch (Exception $e) {
            throw new ParseException('Failed to retrieve subject unit', 0, $e);
        }
    }
}

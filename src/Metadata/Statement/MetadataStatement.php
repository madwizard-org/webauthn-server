<?php


namespace MadWizard\WebAuthn\Metadata\Statement;

use MadWizard\WebAuthn\Attestation\AttestationType;
use MadWizard\WebAuthn\Attestation\Identifier\Aaguid;
use MadWizard\WebAuthn\Attestation\Identifier\Aaid;
use MadWizard\WebAuthn\Attestation\Identifier\AttestationKeyIdentifier;
use MadWizard\WebAuthn\Attestation\Identifier\IdentifierInterface;
use MadWizard\WebAuthn\Attestation\TrustAnchor\CertificateTrustAnchor;
use MadWizard\WebAuthn\Attestation\TrustAnchor\MetadataInterface;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Format\DataValidator;
use MadWizard\WebAuthn\Pki\X509Certificate;
use function base64_decode;
use function in_array;

class MetadataStatement implements MetadataInterface
{
    /** @var null|Aaid */
    private $aaid;

    /** @var null|Aaguid */
    private $aaguid;

    /** @var null|AttestationKeyIdentifier[] */
    private $attestationCertificateKeyIdentifiers;

    /** @var string */
    private $description;

//    /** @var int */
//    private $authenticatorVersion;
//
//    /** @var null|string */
//    private $protocolFamily;
//
//    /** @var Version[] */
//    private $upv;
//
//    /** @var string */
//    private $assertionScheme;
//

    /** @var int */
    private $authenticationAlgorithm;

//
//    /** @var int */
//    private $publicKeyAlgAndEncoding;
//

    /** @var int[] */
    private $attestationTypes;

//
//    /** @var VerificationMethodDescriptor[] */
//    private $userVerificationDetails;
//
//    /** @var int */
//    private $keyProtection;
//
//    /** @var null|boolean */
//    private $isKeyRestricted;
//
//    /** @var null|boolean */
//    private $isFreshUserVerificationRequired;
//
//    /** @var int */
//    private $matcherProtection;
//
//    /** @var int */
//    private $attachmentHint;         // TODO 32-bit unsigned problem?
//
//    /** @var boolean */
//    private $isSecondFactorOnly;
//
//    /** @var int */
//    private $tcDisplay;
//
//    /** @var null|string */
//    private $tcDisplayContentType;
//
//    /** @var null|DisplayPNGCharacteristicsDescriptor[] */
//    private $tcDisplayPNGCharacteristics;
//

    /** @var string[] */
    private $attestationRootCertificates;

//
//    /** @var null|EcdaaTrustAnchor[] */
//    private $ecdaaTrustAnchors;
//
//    /** @var null|string */
//    private $icon;
//
//    /** @var null|ExtensionDescriptor[] */
//    private $supportedExtensions;

    private $statusReports = [];

    public static function decodeString(string $json) : self
    {
        $data = \json_decode($json, true, 20);
        if (!\is_array($data)) {
            throw new ParseException('Invalid JSON metadata statement.');
        }
        return self::decodeJson($data);
    }

    public static function decodeJson(array $data) : self
    {
        if (is_string($data['isSecondFactorOnly'] ?? null)) {
            $data['isSecondFactorOnly'] = (bool) $data['isSecondFactorOnly']; // TODO
        }
        DataValidator::checkTypes(
            $data,
            [
                'aaid' => '?string',   // !!!!
                'aaguid' => '?string', // !!!!
                'attestationCertificateKeyIdentifiers' => '?array',  // !!!!
                'description' => 'string',
                'authenticatorVersion' => 'integer',
                'protocolFamily' => '?string',
                'upv' => 'array', // !!!!
                'assertionScheme' => 'string',
                'authenticationAlgorithm' => 'integer',
                'publicKeyAlgAndEncoding' => 'integer',
                'attestationTypes' => 'array',  // !!!!
                'userVerificationDetails' => 'array', // !!!!
                'keyProtection' => 'integer',
                'isKeyRestricted' => '?boolean',
                'isFreshUserVerificationRequired' => '?boolean',
                'matcherProtection' => 'integer',
                'attachmentHint' => 'integer',
                'isSecondFactorOnly' => 'boolean',
                'tcDisplay' => 'integer',
                'tcDisplayContentType' => '?string',
                'tcDisplayPNGCharacteristics' => '?array',  // !!!!
                'attestationRootCertificates' => 'array', // !!!!
                'ecdaaTrustAnchors' => '?array', // !!!!
                'icon' => '?string',
                'supportedExtensions[]' => '?array', // !!!!
            ],
            false
        );

        $statement = new self();
        $statement->aaid = self::validateAaid($data['aaid'] ?? null);
        $statement->aaguid = self::validateAaguid($data['aaguid'] ?? null);
        $statement->attestationCertificateKeyIdentifiers = self::validateKeyIdentifiers($data['attestationCertificateKeyIdentifiers'] ?? null);
        $statement->attestationTypes = self::validateAttestationTypes($data['attestationTypes']);
        $statement->description = $data['description'];
        $statement->authenticationAlgorithm = $data['authenticationAlgorithm'];
        $statement->attestationRootCertificates = self::parseRootCertificates($data['attestationRootCertificates']);

        // TODO:check at least one of aaid, aaguid or keyidentifiers set
        return $statement;
    }

    private static function validateAaguid(?string $aaguid) : ?Aaguid
    {
        if ($aaguid === null) {
            return null;
        }
        return Aaguid::parseString($aaguid);
    }

    private static function validateAaid(?string $aaid) : ?Aaid
    {
        if ($aaid === null) {
            return null;
        }
        return new Aaid($aaid);
    }

    private static function validateKeyIdentifiers(?array $list) : ?array
    {
        if ($list === null) {
            return $list;
        }

        $result = [];
        foreach ($list as $item) {
            $result[] = new AttestationKeyIdentifier($item);
        }
        return $result;
    }

    private static function validateAttestationTypes(array $types) : array
    {
        foreach ($types as $type) {
            if (!is_int($type)) {
                throw new ParseException('Invalid attestation type in attestationTypes');
            }
        }
        return $types;
    }

    private static function parseRootCertificates(array $list) : array
    {
        foreach ($list as $item) {
            if (!is_string($item)) {
                throw new ParseException('Expecting string in attestationRootCertificates.');
            }
            if (@base64_decode($item) === false) {
                throw new ParseException('Invalid base64 encoded string in attestationRootCertificates.');
            }
        }
        return $list;
    }

    /**
     * @return IdentifierInterface[]
     */
    public function getIdentifiers() : array
    {
        $ids = [];
        if ($this->aaguid !== null) {
            $ids[] = $this->aaguid;
        }

        if ($this->aaid !== null) {
            $ids[] = $this->aaid;
        }
        $keyIds = $this->attestationCertificateKeyIdentifiers;
        if ($keyIds !== null) {
            $ids = array_merge($ids, $keyIds);
        }
        return $ids;
    }

    public function matchesIdentifier(IdentifierInterface $identifier): bool
    {
        foreach ($this->getIdentifiers() as $candidate) {
            if ($identifier->equals($candidate)) {
                return true;
            }
        }
        return false;
    }

    /**
     * @return Aaid|null
     */
    public function getAaid(): ?Aaid
    {
        return $this->aaid;
    }

    /**
     * @return Aaguid|null
     */
    public function getAaguid(): ?Aaguid
    {
        return $this->aaguid;
    }

    /**
     * @return AttestationKeyIdentifier[]|null
     */
    public function getAttestationCertificateKeyIdentifiers(): ?array
    {
        return $this->attestationCertificateKeyIdentifiers;
    }

    /**
     * @return int[]
     * @see AttestationConstant
     */
    public function getAttestationTypes(): array
    {
        return $this->attestationTypes;
    }

    /**
     * @param string $type Attestation type
     * @return bool True if the authenticator supports the given attestation type.
     * @see AttestationType
     */
    public function supportsAttestationType(string $type) : bool
    {
        return in_array(AttestationConstant::convertType($type), $this->attestationTypes, true);
    }

    public function getDescription() : string
    {
        return $this->description;
    }

    /**
     * @return string[]
     */
    public function getAttestationRootCertificates(): array
    {
        return $this->attestationRootCertificates;
    }

    public function getTrustAnchors(): array
    {
        $trustAnchors = [];
        foreach ($this->getAttestationRootCertificates() as $pem) {
            $trustAnchors[] = new CertificateTrustAnchor(X509Certificate::fromBase64($pem));
        }
        return $trustAnchors;
    }

    /**
     * @return StatusReport[]
     */
    public function getStatusReports(): array
    {
        return $this->statusReports;
    }

    /**
     * @param StatusReport[] $statusReports
     */
    public function setStatusReports(array $statusReports): void
    {
        $this->statusReports = $statusReports;
    }
}

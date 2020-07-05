<?php


namespace MadWizard\WebAuthn\Attestation\Android;

use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\UnspecifiedType;

class AndroidExtensionParser implements AndroidExtensionParserInterface
{
    // Sequence indices in KeyDescription. See https://source.android.com/security/keystore/attestation#attestation-extension
    private const IDX_ATTESTATION_CHALLENGE = 4;

    private const IDX_SOFTWARE_ENFORCED = 6;

    private const IDX_TEE_INFORCED = 7;

    // Tags in AuthorizationList
    private const TAG_PURPOSE = 1;

    private const TAG_ALL_APPLICATIONS = 600;

    private const TAG_ORIGIN = 702;

    private function parseAuthorizationList(Sequence $seq) : AuthorizationList
    {
        $authList = new AuthorizationList();

        // purpose [1] EXPLICIT SET OF INTEGER OPTIONAL
        //file_put_contents('derrr', ($seq->toDER()));
        if ($seq->hasTagged(self::TAG_PURPOSE)) {
            $set = $seq->getTagged(self::TAG_PURPOSE)->asExplicit()->asSet();
            foreach ($set->elements() as $element) {
                $authList->addPurpose($element->asInteger()->intNumber());
            }
        }

        // allApplications [600] EXPLICIT NULL OPTIONAL
        if ($seq->hasTagged(self::TAG_ALL_APPLICATIONS)) {
            // When present, verify that value is NULL
            $seq->getTagged(self::TAG_ALL_APPLICATIONS)->asExplicit()->asNull();
            $authList->setAllApplications(true);
        }

        // origin [702] EXPLICIT INTEGER OPTIONAL
        if ($seq->hasTagged(self::TAG_ORIGIN)) {
            $origin = $seq->getTagged(self::TAG_ORIGIN)->asExplicit()->asInteger()->intNumber();
            $authList->setOrigin($origin);
        }

        return $authList;
    }

    public function parseAttestationExtension(ByteBuffer $data) : AndroidAttestationExtension
    {
        try {
            $der = $data->getBinaryString();
            $seq = UnspecifiedType::fromDER($der)->asSequence();

            $challenge = $seq->at(self::IDX_ATTESTATION_CHALLENGE)->asOctetString()->string();

            $software = $this->parseAuthorizationList($seq->at(self::IDX_SOFTWARE_ENFORCED)->asSequence());
            $tee = $this->parseAuthorizationList($seq->at(self::IDX_TEE_INFORCED)->asSequence());
        } catch (\Exception $e) {
            throw new ParseException('Failed to parse Android attestation extension.', 0, $e);
        }

        return new AndroidAttestationExtension(new ByteBuffer($challenge), $software, $tee);
    }
}

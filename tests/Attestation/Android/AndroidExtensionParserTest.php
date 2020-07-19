<?php

namespace MadWizard\WebAuthn\Tests\Attestation\Android;

use MadWizard\WebAuthn\Attestation\Android\AndroidExtensionParser;
use MadWizard\WebAuthn\Attestation\Android\AuthorizationList;
use MadWizard\WebAuthn\Tests\Helper\HexData;
use PHPUnit\Framework\TestCase;

class AndroidExtensionParserTest extends TestCase
{
    /**
     * @var AndroidExtensionParser
     */
    private $parser;

    protected function setUp(): void
    {
        $this->parser = new AndroidExtensionParser();
    }

    public function testExample()
    {
        $test = HexData::buf(
            '3081ea0201020a01000201010a010104
             202a4382d7bbd89d8b5bdf1772cfecca
             14392487b9fd571f2eb72bdf97de06d4
             b60400308182bf831008020601676e2e
             e170bf831108020601b0ea8dad70bf83
             1208020601b0ea8dad70bf853d080206
             01676e2edfe8bf85454e044c304a3124
             3022041d636f6d2e676f6f676c652e61
             74746573746174696f6e6578616d706c
             65020101312204205ad05ec221c8f83a
             226127dec557500c3e574bc60125a9dc
             21cb0be4a00660953033a10531030201
             02a203020103a30402020100a5053103
             020104aa03020101bf837803020117bf
             83790302011ebf853e03020100'
        );

        $ext = $this->parser->parseAttestationExtension($test);
        $this->assertSame('2a4382d7bbd89d8b5bdf1772cfecca14392487b9fd571f2eb72bdf97de06d4b6', $ext->getChallenge()->getHex());

        $list = $ext->getSoftwareEnforcedAuthList();
        $this->assertNull($list->getOrigin());
        $this->assertSame(false, $list->hasAllApplications());
        $this->assertFalse($list->hasPurpose(AuthorizationList::KM_PURPOSE_SIGN));
        $this->assertSame([], $list->getPurposeList());

        $list = $ext->getTeeEnforcedAuthList();
        $this->assertSame(AuthorizationList::KM_ORIGIN_GENERATED, $list->getOrigin());
        $this->assertSame(false, $list->hasAllApplications());
        $this->assertTrue($list->hasPurpose(AuthorizationList::KM_PURPOSE_SIGN));
        $this->assertFalse($list->hasPurpose(5));
        $this->assertSame([AuthorizationList::KM_PURPOSE_SIGN], $list->getPurposeList());
    }

//    public function testMinimal()
//    {
//        $seq = UnspecifiedType::fromDER(HexData::bin(
//            '3081ea0201020a01000201010a010104
//             202a4382d7bbd89d8b5bdf1772cfecca
//             14392487b9fd571f2eb72bdf97de06d4
//             b60400308182bf831008020601676e2e
//             e170bf831108020601b0ea8dad70bf83
//             1208020601b0ea8dad70bf853d080206
//             01676e2edfe8bf85454e044c304a3124
//             3022041d636f6d2e676f6f676c652e61
//             74746573746174696f6e6578616d706c
//             65020101312204205ad05ec221c8f83a
//             226127dec557500c3e574bc60125a9dc
//             21cb0be4a00660953033a10531030201
//             02a203020103a30402020100a5053103
//             020104aa03020101bf837803020117bf
//             83790302011ebf853e03020100'
//        ))->asSequence();
//
//
//        $seq = $seq->withReplaced(7, $seq->at(7)->asSequence()->withInserted(7, new ExplicitlyTaggedType(600, new NullType())));
//
//        die(chunk_split(bin2hex($seq->toDER()), 64));
//    }
}

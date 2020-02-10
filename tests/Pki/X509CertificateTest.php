<?php


namespace MadWizard\WebAuthn\Tests\Pki;

use MadWizard\WebAuthn\Pki\X509Certificate;
use PHPStan\Testing\TestCase;

class X509CertificateTest extends TestCase
{
    private const PEM = "-----BEGIN CERTIFICATE-----\n" .
            "MIIBxDCCAWqgAwIBAgIJANsJjc59mr6uMAoGCCqGSM49BAMCMD0xCzAJBgNVBAYT\n" .
            "Ak5MMQowCAYDVQQIDAFBMQowCAYDVQQHDAFCMQowCAYDVQQKDAFDMQowCAYDVQQD\n" .
            "DAFEMB4XDTE5MTAwNjE2MzIwN1oXDTIwMTAwNTE2MzIwN1owPTELMAkGA1UEBhMC\n" .
            "TkwxCjAIBgNVBAgMAUExCjAIBgNVBAcMAUIxCjAIBgNVBAoMAUMxCjAIBgNVBAMM\n" .
            "AUQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAROOizEriU76pCOP2IhrpBnolOp\n" .
            "jbzX3FqfRd4n66vXHdc0KOmkAAoIEBBMfrey36AxmAUUu2BEE8KgtzJ8J5L+o1Mw\n" .
            "UTAdBgNVHQ4EFgQUGRLcifZuy4Qm+HRNN/xbdvUfjtIwHwYDVR0jBBgwFoAUGRLc\n" .
            "ifZuy4Qm+HRNN/xbdvUfjtIwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNI\n" .
            "ADBFAiEAglju4WSb/d1ly5nHliJVIq7GRxA73cbQs9f6cXLz6iMCIAOLtWbkaSvq\n" .
            "dGwXgPXrTgx5cvEnKjdHkDshN30MVmfr\n" .
            "-----END CERTIFICATE-----\n";

    private const BASE64 =
        'MIIBxDCCAWqgAwIBAgIJANsJjc59mr6uMAoGCCqGSM49BAMCMD0xCzAJBgNVBAYT' .
        'Ak5MMQowCAYDVQQIDAFBMQowCAYDVQQHDAFCMQowCAYDVQQKDAFDMQowCAYDVQQD' .
        'DAFEMB4XDTE5MTAwNjE2MzIwN1oXDTIwMTAwNTE2MzIwN1owPTELMAkGA1UEBhMC' .
        'TkwxCjAIBgNVBAgMAUExCjAIBgNVBAcMAUIxCjAIBgNVBAoMAUMxCjAIBgNVBAMM' .
        'AUQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAROOizEriU76pCOP2IhrpBnolOp' .
        'jbzX3FqfRd4n66vXHdc0KOmkAAoIEBBMfrey36AxmAUUu2BEE8KgtzJ8J5L+o1Mw' .
        'UTAdBgNVHQ4EFgQUGRLcifZuy4Qm+HRNN/xbdvUfjtIwHwYDVR0jBBgwFoAUGRLc' .
        'ifZuy4Qm+HRNN/xbdvUfjtIwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNI' .
        'ADBFAiEAglju4WSb/d1ly5nHliJVIq7GRxA73cbQs9f6cXLz6iMCIAOLtWbkaSvq' .
        'dGwXgPXrTgx5cvEnKjdHkDshN30MVmfr';

    public function testPem()
    {
        $cert = X509Certificate::fromPem(self::PEM);
        $this->assertSame(self::PEM, $cert->asPem());
        $this->assertSame(base64_decode(self::BASE64), $cert->asDer());
    }

    public function testDer()
    {
        $cert = X509Certificate::fromDer(base64_decode(self::BASE64));
        $this->assertSame(self::PEM, $cert->asPem());
        $this->assertSame(base64_decode(self::BASE64), $cert->asDer());
    }

    public function testBase64()
    {
        $cert = X509Certificate::fromBase64(self::BASE64);
        $this->assertSame(self::PEM, $cert->asPem());
        $this->assertSame(base64_decode(self::BASE64), $cert->asDer());
    }

    public function testSerialize()
    {
        $cert = X509Certificate::fromPem(self::PEM);
        $cert = unserialize(serialize($cert));
        $this->assertSame(self::PEM, $cert->asPem());
    }
}

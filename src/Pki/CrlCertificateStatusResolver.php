<?php

namespace MadWizard\WebAuthn\Pki;

use DateTimeImmutable;
use Exception;
use MadWizard\WebAuthn\Cache\CacheProviderInterface;
use MadWizard\WebAuthn\Exception\RemoteException;
use MadWizard\WebAuthn\Exception\UnsupportedException;
use MadWizard\WebAuthn\Exception\VerificationException;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Remote\DownloaderInterface;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Sop\X509\Certificate\Certificate;

/**
 * @experimental
 */
final class CrlCertificateStatusResolver implements CertificateStatusResolverInterface, LoggerAwareInterface
{
    /** @var CacheItemPoolInterface */
    private $cache;

    /**
     * @var DownloaderInterface
     */
    private $downloader;

    /**
     * @var LoggerInterface
     */
    private $logger;

    /**
     * @var bool
     */
    private $silentFailure;

    /**
     * @experimental
     */
    public function __construct(DownloaderInterface $downloader, CacheProviderInterface $cacheProvider, bool $silentFailure = false)
    {
        if (!class_exists(\phpseclib3\File\X509::class)) {
            throw new UnsupportedException('CRL support requires phpseclib v3. Use composer require phpseclib/phpseclib ^3.0');
        }

        $this->downloader = $downloader;
        $this->cache = $cacheProvider->getCachePool('crl');
        $this->logger = new NullLogger();
        $this->silentFailure = $silentFailure;
    }

    /**
     * @experimental
     */
    public function setLogger(LoggerInterface $logger): void
    {
        $this->logger = $logger;
    }

    /**
     * @experimental
     */
    public function isRevoked(X509Certificate $subject, X509Certificate ...$caCertificates): bool
    {
        try {
            $cert = Certificate::fromDER($subject->asDer());
            $csn = $cert->tbsCertificate()->serialNumber();
        } catch (Exception $e) {
            throw new VerificationException(sprintf('Failed to parse certificate: %s', $e->getMessage()), 0, $e);
        }

        try {
            $urls = $this->getCrlUrlList($cert);
        } catch (VerificationException $e) {
            $this->logger->warning(
                'Failed to get CRL distribution points: {message}',
                [
                    'message' => $e->getMessage(),
                    'exception' => $e,
                ]
            );
            if ($this->silentFailure) {
                return false;
            }
            throw new VerificationException('Failed to get CRL distribution points: ' . $e->getMessage(), 0, $e);
        }

        foreach ($urls as $url) {
            try {
                $crl = $this->retrieveCrl($url, ...$caCertificates);

                if ($crl->isRevoked($csn)) {
                    $this->logger->warning(
                        'Certificate {serial} with subject "{subject}" is revoked.',
                        [
                            'serial' => $csn,
                            'subject' => $cert->tbsCertificate()->subject(),
                        ]
                    );
                    return true;
                }
            } catch (WebAuthnException $e) {
                if ($this->silentFailure) {
                    continue;
                }
                throw new VerificationException(sprintf('Failed to retrieve CRL %s:' . PHP_EOL . '%s', $url, $e->getMessage()), 0, $e);
            }
        }
        return false;
    }

    private function retrieveCrl(string $url, X509Certificate ...$caCertificates): Crl
    {
        $urlHash = hash('sha256', $url);
        $item = $this->cache->getItem($urlHash);

        $crlData = null;
        if ($item->isHit()) {
            $data = $item->get();
            if ($data['nextUpdate'] > new DateTimeImmutable()) {           // TODO: abstract time for unit tests
                $this->logger->debug('Using CRL from cache {url} (next update {date}).', ['url' => $url, 'date' => $data['nextUpdate']->format('Y-m-d H:i:s')]);
                $crlData = $data['data'];
            }
        }

        if ($crlData === null) {
            try {
                $this->logger->debug('Retrieving CRL from {url}', ['url' => $url]);
                $crlFile = $this->downloader->downloadFile($url);
            } catch (RemoteException $e) {
                $this->logger->warning('Failed to download CRL for certificate from {url}: {error}',
                    ['url' => $url, 'error' => $e->getMessage()]);
                throw new VerificationException(sprintf('Failed to download CRL for certificate from %s: %s', $url, $e->getMessage()));
            }
            $crlData = $crlFile->getData();
        }

        $crl = new Crl($crlData, ...$caCertificates);

        if (!$item->isHit()) {
            $item->set([
                'nextUpdate' => $crl->getNextUpdate(),
                'data' => $crlData,
            ]);
            $item->expiresAt($crl->getNextUpdate());
            $this->cache->save($item);
        }
        return $crl;
    }

    /**
     * @return string[]
     */
    private function getCrlUrlList(Certificate $subject): array
    {
        try {
            $urls = [];

            $extensions = $subject->tbsCertificate()->extensions();
            if ($extensions->hasCRLDistributionPoints()) {
                $crlDists = $extensions->crlDistributionPoints();
                foreach ($crlDists->distributionPoints() as $dist) {
                    $url = $dist->fullName()->names()->firstURI();
                    $scheme = parse_url($url, PHP_URL_SCHEME);
                    if (!in_array($scheme, ['http', 'https'], true)) {
                        $this->logger->warning('Ignoring non-http CRL URI {url}.', ['url' => $url]);
                        continue;
                    }
                    $urls[] = $url;
                }
            }
            return $urls;
        } catch (Exception $e) {
            throw new VerificationException('Failed to get CRL distribution points from certificate: ' . $e->getMessage(), 0, $e);
        }
    }
}

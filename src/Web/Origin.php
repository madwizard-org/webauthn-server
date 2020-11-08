<?php

namespace MadWizard\WebAuthn\Web;

use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Format\SerializableTrait;
use Serializable;
use function mb_strtolower;

final class Origin implements Serializable
{
    use SerializableTrait;

    /**
     * @var string
     */
    private $scheme;

    /**
     * @var string
     */
    private $host;

    /**
     * @var int
     */
    private $port;

    private const PARSE_REGEXP = '#^(?<scheme>[A-Za-z][-._~0-9A-Za-z]*)://(?<host>([^:]+))(:(?<port>[0-9]{1,5}))?$#';

    private function __construct(string $scheme, string $host, int $port)
    {
        $this->scheme = $scheme;
        $this->host = $host;
        $this->port = $port;
    }

    // TODO: stricter parsing/canonalization according to spec
    public static function parse(string $origin): Origin
    {
        [$scheme, $host, $port] = self::parseElements($origin);

        if (!self::isValidHost($host)) {
            throw new ParseException(sprintf("Invalid host name '%s'.", $host));
        }
        if ($port === null) {
            $port = self::defaultPort($scheme);
        }

        if ($port === 0 || $port >= 2 ** 16) {
            throw new ParseException(sprintf('Invalid port number %d.', $port));
        }
        return new Origin($scheme, $host, $port);
    }

    private static function defaultPort(string $scheme): int
    {
        if ($scheme === 'https') {
            return 443;
        }
        if ($scheme === 'http') {
            return 80;
        }
        throw new ParseException(sprintf("No default port number for scheme '%s'.", $scheme));
    }

    private static function isValidHost(string $host): bool
    {
        if ($host === '') {
            return false;
        }

        if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return true;
        }

        // TODO ipv6 - needs adjustment in regexp
//      if ($host[0] === '[' && $host[-1] === ']' && filter_var(substr($host, 1, -1), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
//          return true;
//      }
        if (filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
            return true;
        }
        return false;
    }

    private static function parseElements(string $origin): array
    {
        if (!preg_match(self::PARSE_REGEXP, $origin, $matches)) {
            throw new ParseException(sprintf("Could not parse origin '%s'.", $origin));
        }
        $scheme = strtolower($matches['scheme']);
        $host = mb_strtolower($matches['host'], 'UTF-8');

        $port = isset($matches['port']) ? (int) $matches['port'] : null;
        return [$scheme, $host, $port];
    }

    public function equals(Origin $origin): bool
    {
        return $this->host === $origin->host &&
            $this->port === $origin->port &&
            $this->scheme === $origin->scheme;
    }

    public function toString(): string
    {
        if ($this->usesDefaultPort()) {
            return sprintf('%s://%s', $this->scheme, $this->host);
        }
        return sprintf('%s://%s:%d', $this->scheme, $this->host, $this->port);
    }

    private function usesDefaultPort(): bool
    {
        if ($this->scheme === 'http' && $this->port === 80) {
            return true;
        }
        if ($this->scheme === 'https' && $this->port === 443) {
            return true;
        }
        return false;
    }

    public function getHost(): string
    {
        return $this->host;
    }

    public function getScheme(): string
    {
        return $this->scheme;
    }

    public function getPort(): int
    {
        return $this->port;
    }

    public function __serialize(): array
    {
        return [
            'scheme' => $this->scheme,
            'host' => $this->host,
            'port' => $this->port,
        ];
    }

    public function __unserialize(array $data): void
    {
        $this->scheme = $data['scheme'];
        $this->host = $data['host'];
        $this->port = $data['port'];
    }
}

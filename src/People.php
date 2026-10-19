<?php

declare(strict_types=1);

namespace Oki\People;

use Oki\People\Events\IdentityEvents;
use Oki\People\Http\Transport;
use Oki\People\Keys\KeySet;
use Oki\People\OAuth\Authorization;
use Oki\People\OAuth\ClientCredentials;
use Oki\People\Support\Remembered;
use Oki\People\Tokens\AccessTokenVerifier;
use Oki\People\Tokens\IdTokenVerifier;
use Oki\People\Tokens\Signature;
use Psr\Clock\ClockInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * Everything this SDK does, from one place.
 *
 * Bring your own HTTP client (PSR-18), message factories (PSR-17), cache
 * (PSR-16) and clock (PSR-20). The cache should be shared across requests and
 * processes — a key set fetched per request is a request to People per
 * request.
 */
final class People
{
    private readonly Transport $http;

    private readonly Discovery $discovery;

    private readonly Signature $signature;

    private readonly ClientCredentials $credentials;

    public function __construct(
        public readonly Config $config,
        ClientInterface $client,
        RequestFactoryInterface $requests,
        StreamFactoryInterface $streams,
        CacheInterface $cache,
        ClockInterface $clock,
    ) {
        $this->http = new Transport($client, $requests, $streams);
        $remembered = new Remembered($cache, $clock, $config->keysTtl);
        $this->discovery = new Discovery($config, $this->http, $remembered);
        $this->signature = new Signature($config, new KeySet($this->discovery, $this->http, $remembered), $clock);
        $this->credentials = new ClientCredentials($config, $this->discovery, $this->http, $cache);
    }

    /** Checks access tokens presented to this API. */
    public function accessTokens(): AccessTokenVerifier
    {
        return new AccessTokenVerifier($this->config, $this->signature);
    }

    /** Checks the `id_token` that comes back from signing somebody in. */
    public function idTokens(): IdTokenVerifier
    {
        return new IdTokenVerifier($this->config, $this->signature);
    }

    /** Signs somebody in, refreshes their tokens and signs them out. */
    public function authorization(): Authorization
    {
        return new Authorization($this->config, $this->discovery, $this->http, $this->idTokens());
    }

    /** Tokens this client holds for itself. */
    public function clientCredentials(): ClientCredentials
    {
        return $this->credentials;
    }

    /** What happened to the people who signed in to this application. */
    public function identityEvents(): IdentityEvents
    {
        return new IdentityEvents($this->config, $this->http, $this->credentials);
    }

    /** Who an access token belongs to, asked of People. */
    public function userinfo(): Userinfo
    {
        return new Userinfo($this->discovery, $this->http);
    }

    /** People's discovery document. */
    public function discovery(): Discovery
    {
        return $this->discovery;
    }
}

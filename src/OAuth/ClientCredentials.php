<?php

declare(strict_types=1);

namespace Oki\People\OAuth;

use Oki\People\Config;
use Oki\People\Discovery;
use Oki\People\Exceptions\PeopleRefused;
use Oki\People\Exceptions\PeopleUnreachable;
use Oki\People\Http\Transport;
use Psr\SimpleCache\CacheInterface;

/**
 * A token this client holds for itself, for calls no person is behind.
 *
 * Kept until shortly before it expires, so a busy consumer asks People for
 * one every few minutes rather than once a call.
 */
final readonly class ClientCredentials
{
    /** Seconds before expiry a held token is given up, so it is never sent as it lapses. */
    private const int MARGIN = 30;

    public function __construct(
        private Config $config,
        private Discovery $discovery,
        private Transport $http,
        private CacheInterface $cache,
    ) {}

    /**
     * @param  list<string>  $scopes
     *
     * @throws PeopleRefused when People will not issue one: a public client, or a scope it was not given.
     * @throws PeopleUnreachable
     */
    public function token(array $scopes): string
    {
        $key = $this->key($scopes);

        /** @var mixed $held */
        $held = $this->cache->get($key);

        if (is_string($held) && $held !== '') {
            return $held;
        }

        $tokens = TokenSet::from($this->http->form($this->discovery->endpoint('token_endpoint'), [
            'grant_type' => 'client_credentials',
            'client_id' => $this->config->clientId(),
            'client_secret' => $this->config->clientSecret(),
            'scope' => implode(' ', $scopes),
        ]));

        $life = $tokens->expiresIn - self::MARGIN;

        if ($life > 0) {
            $this->cache->set($key, $tokens->accessToken, $life);
        }

        return $tokens->accessToken;
    }

    /**
     * Gives up the held token, after People refused it: revoked, or the client's secret changed.
     *
     * @param  list<string>  $scopes
     */
    public function forget(array $scopes): void
    {
        $this->cache->delete($this->key($scopes));
    }

    /** @param  list<string>  $scopes */
    private function key(array $scopes): string
    {
        sort($scopes);

        return 'oki-technologies.people.client.'.hash('sha256', $this->config->clientId().' '.implode(' ', $scopes));
    }
}

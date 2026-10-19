<?php

declare(strict_types=1);

namespace Oki\People\Events;

use Oki\People\Config;
use Oki\People\Exceptions\PeopleRefused;
use Oki\People\Exceptions\PeopleUnreachable;
use Oki\People\Http\Transport;
use Oki\People\OAuth\ClientCredentials;

/**
 * What happened to the people who signed in to this application.
 *
 * Read on this client's own token — a confidential client only. People
 * answers about nobody else: not people who never signed in here, and after
 * somebody disconnects this app, nothing about them but their deletion.
 */
final readonly class IdentityEvents
{
    private const array SCOPES = ['identity.events'];

    public function __construct(
        private Config $config,
        private Transport $http,
        private ClientCredentials $credentials,
    ) {}

    /**
     * The events after a sequence, oldest first.
     *
     * @throws PeopleRefused|PeopleUnreachable
     */
    public function after(int $sequence = 0, int $limit = 100): EventPage
    {
        try {
            $body = $this->read($sequence, $limit);
        } catch (PeopleRefused $refused) {
            if ($refused->status !== 401) {
                throw $refused;
            }

            // The held token was revoked or has lapsed early. One more try, on a new one.
            $this->credentials->forget(self::SCOPES);
            $body = $this->read($sequence, $limit);
        }

        $events = [];

        foreach (is_array($body['data'] ?? null) ? $body['data'] : [] as $event) {
            $read = is_array($event) ? IdentityEvent::from($event) : null;

            if ($read !== null) {
                $events[] = $read;
            }
        }

        $next = is_array($body['meta'] ?? null) ? ($body['meta']['next'] ?? null) : null;

        return new EventPage($events, is_int($next) ? $next : null);
    }

    /** @return array<mixed> */
    private function read(int $sequence, int $limit): array
    {
        return $this->http->get(
            $this->config->issuer().'/v1/identity/events?'.http_build_query(['after' => $sequence, 'limit' => $limit]),
            ['Authorization' => 'Bearer '.$this->credentials->token(self::SCOPES)],
        );
    }
}

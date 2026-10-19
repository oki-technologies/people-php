<?php

declare(strict_types=1);

namespace Oki\People\Keys;

use Oki\People\Discovery;
use Oki\People\Exceptions\PeopleUnreachable;
use Oki\People\Http\Transport;
use Oki\People\Support\Remembered;

/**
 * The keys People signs with, read from its JWKS.
 *
 * A token's `kid` picks one. A `kid` not yet seen is fetched the first time a
 * token names it, so a key rotation at People needs nothing done here; a key
 * People stops publishing stops verifying once the set is next read.
 */
final readonly class KeySet
{
    private const string KEY = 'okitechnologies.people.jwks';

    public function __construct(
        private Discovery $discovery,
        private Transport $http,
        private Remembered $remembered,
    ) {}

    /**
     * The public keys, as PEM, that may have signed a token naming this `kid`.
     *
     * A token naming no `kid` may have been signed by any of them.
     *
     * @return list<non-empty-string>
     */
    public function for(?string $kid): array
    {
        $keys = $this->keys();

        if ($kid === null) {
            return array_values($keys);
        }

        if (! isset($keys[$kid])) {
            // A key published since the last read, or a forgery naming one.
            $keys = $this->keys(refresh: true);
        }

        return isset($keys[$kid]) ? [$keys[$kid]] : [];
    }

    /** @return array<string, non-empty-string> */
    private function keys(bool $refresh = false): array
    {
        $keys = $this->remembered->get(self::KEY, $this->fetch(...), $refresh) ?? [];

        return array_filter($keys, fn (mixed $pem, mixed $kid): bool => is_string($kid) && is_string($pem) && $pem !== '', ARRAY_FILTER_USE_BOTH);
    }

    /**
     * @return array<string, non-empty-string>
     *
     * @throws PeopleUnreachable
     */
    private function fetch(): array
    {
        $published = $this->http->get($this->discovery->endpoint('jwks_uri'))['keys'] ?? null;
        $keys = [];

        foreach (is_array($published) ? $published : [] as $jwk) {
            $read = is_array($jwk) ? Jwk::read($jwk) : null;

            if ($read !== null) {
                $keys[$read[0]] = $read[1];
            }
        }

        // A set with nothing usable in it is a fault over there, not a rotation to nothing.
        return $keys !== [] ? $keys : throw new PeopleUnreachable('People published no key that can verify a token.');
    }
}

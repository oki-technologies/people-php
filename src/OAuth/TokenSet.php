<?php

declare(strict_types=1);

namespace Oki\People\OAuth;

use Oki\People\Exceptions\PeopleUnreachable;
use Oki\People\Tokens\Identity;

/**
 * What People's token endpoint answered.
 *
 * `identity` is the verified `id_token`, when `openid` was granted.
 */
final readonly class TokenSet
{
    /**
     * @param  list<string>  $scopes
     */
    public function __construct(
        public string $accessToken,
        public int $expiresIn,
        public ?string $refreshToken = null,
        public ?string $idToken = null,
        public array $scopes = [],
        public ?Identity $identity = null,
    ) {}

    /**
     * @param  array<mixed>  $body
     *
     * @throws PeopleUnreachable
     */
    public static function from(array $body, ?Identity $identity = null): self
    {
        $access = $body['access_token'] ?? null;

        if (! is_string($access) || $access === '') {
            throw new PeopleUnreachable('People\'s token endpoint answered with no access token.');
        }

        $text = fn (string $key): ?string => is_string($body[$key] ?? null) && $body[$key] !== '' ? $body[$key] : null;
        $scope = $text('scope');

        return new self(
            accessToken: $access,
            expiresIn: is_int($body['expires_in'] ?? null) ? $body['expires_in'] : 0,
            refreshToken: $text('refresh_token'),
            idToken: $text('id_token'),
            scopes: $scope === null ? [] : array_values(array_filter(explode(' ', $scope))),
            identity: $identity,
        );
    }
}

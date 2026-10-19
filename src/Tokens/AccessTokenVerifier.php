<?php

declare(strict_types=1);

namespace Oki\People\Tokens;

use DateTimeImmutable;
use Lcobucci\JWT\UnencryptedToken;
use Oki\People\Config;
use Oki\People\Exceptions\TokenRejected;

/**
 * Checks an access token presented to this API, without asking People.
 *
 * Genuine, unexpired, issued by the People configured, and addressed to this
 * API by its `audience`. A token naming another API is refused, and so is one
 * naming none: an unaddressed token is one every API would have to accept on
 * trust.
 *
 * What it cannot know is revocation — a token People has since revoked still
 * verifies until it expires, which is why People's access tokens are short.
 */
final readonly class AccessTokenVerifier
{
    public function __construct(
        private Config $config,
        private Signature $signature,
    ) {}

    /**
     * @throws TokenRejected
     */
    public function verify(string $jwt): AccessToken
    {
        $token = $this->signature->verify($jwt);
        $audiences = self::strings($token->claims()->get('aud', []));
        $audience = $this->config->audience;

        if ($audience === null || $audience === '') {
            throw new TokenRejected('This application is configured with no audience, so no access token can be meant for it.');
        }

        if ($audiences === []) {
            throw new TokenRejected('The token names no audience.');
        }

        if (! in_array($audience, $audiences, true)) {
            throw new TokenRejected('The token was not meant for this API.');
        }

        /** @var mixed $subject */
        $subject = $token->claims()->get('sub');

        if (! is_string($subject) || $subject === '') {
            throw new TokenRejected('The token names nobody.');
        }

        /** @var mixed $client */
        $client = $token->claims()->get('client_id');

        return new AccessToken(
            jwt: $jwt,
            subject: $subject,
            clientId: is_string($client) && $client !== '' ? $client : null,
            scopes: self::strings($token->claims()->get('scopes', [])),
            audiences: $audiences,
            expiresAt: self::expiry($token),
            claims: $token->claims()->all(),
        );
    }

    /** @return list<string> */
    private static function strings(mixed $value): array
    {
        return array_values(array_filter(is_array($value) ? $value : [], is_string(...)));
    }

    private static function expiry(UnencryptedToken $token): DateTimeImmutable
    {
        /** @var mixed $expires */
        $expires = $token->claims()->get('exp');

        return $expires instanceof DateTimeImmutable ? $expires : throw new TokenRejected('The token never expires.');
    }
}

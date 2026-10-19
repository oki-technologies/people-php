<?php

declare(strict_types=1);

namespace Oki\People\Tokens;

use DateTimeInterface;
use Oki\People\Config;
use Oki\People\Exceptions\TokenRejected;

/**
 * Checks the `id_token` People hands back beside an access token.
 *
 * Addressed to this client, carrying the `nonce` this client sent — so an
 * answer to somebody else's sign-in cannot be replayed into this one — and
 * bound by `at_hash` to the access token it came with.
 */
final readonly class IdTokenVerifier
{
    public function __construct(
        private Config $config,
        private Signature $signature,
    ) {}

    /**
     * @param  string|null  $nonce  The nonce sent with the authorization request. Required when one was sent.
     * @param  string|null  $accessToken  The access token it arrived with, to check `at_hash` against.
     *
     * @throws TokenRejected
     */
    public function verify(string $idToken, ?string $nonce = null, ?string $accessToken = null): Identity
    {
        $token = $this->signature->verify($idToken);
        $claims = $token->claims();

        if (! $token->isPermittedFor($this->config->clientId())) {
            throw new TokenRejected('The id_token was issued to another client.');
        }

        if ($nonce !== null && $claims->get('nonce') !== $nonce) {
            throw new TokenRejected('The id_token answers another sign-in.');
        }

        if ($accessToken !== null && $claims->get('at_hash') !== self::atHash($accessToken)) {
            throw new TokenRejected('The id_token belongs with another access token.');
        }

        return Identity::from(array_map(
            fn (mixed $value): mixed => $value instanceof DateTimeInterface ? $value->getTimestamp() : $value,
            $claims->all(),
        ));
    }

    /** The left-most half of the access token's SHA-256, base64url — OIDC's `at_hash`. */
    public static function atHash(string $accessToken): string
    {
        return rtrim(strtr(base64_encode(substr(hash('sha256', $accessToken, true), 0, 16)), '+/', '-_'), '=');
    }
}

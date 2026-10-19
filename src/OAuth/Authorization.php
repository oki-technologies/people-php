<?php

declare(strict_types=1);

namespace Oki\People\OAuth;

use Oki\People\Config;
use Oki\People\Discovery;
use Oki\People\Exceptions\PeopleRefused;
use Oki\People\Exceptions\PeopleUnreachable;
use Oki\People\Exceptions\TokenRejected;
use Oki\People\Http\Transport;
use Oki\People\Tokens\IdTokenVerifier;

/**
 * Signing somebody in: authorization code with PKCE, and nothing else.
 *
 * S256 always — People offers no `plain`. A confidential client sends its
 * secret as well; a public one (a mobile app, a single-page app's backend
 * that holds no secret) relies on PKCE alone.
 */
final readonly class Authorization
{
    public function __construct(
        private Config $config,
        private Discovery $discovery,
        private Transport $http,
        private IdTokenVerifier $idTokens,
    ) {}

    /**
     * The address to send somebody to, with a fresh state, nonce and verifier.
     *
     * @param  list<string>  $scopes
     */
    public function begin(string $redirectUri, array $scopes = ['openid', 'profile', 'email']): AuthorizationRequest
    {
        $state = self::random();
        $nonce = self::random();
        $verifier = self::random(48);

        $url = $this->discovery->endpoint('authorization_endpoint').'?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $this->config->clientId(),
            'redirect_uri' => $redirectUri,
            'scope' => implode(' ', $scopes),
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => self::challenge($verifier),
            'code_challenge_method' => 'S256',
        ], encoding_type: PHP_QUERY_RFC3986);

        return new AuthorizationRequest($url, $state, $nonce, $verifier, $redirectUri);
    }

    /**
     * Trades the code People sent back for tokens.
     *
     * @param  array<string, mixed>  $query  The callback's query string, as received.
     *
     * @throws PeopleRefused when People refused the sign-in or the code.
     * @throws TokenRejected when the `state` or the `id_token` does not belong to this sign-in.
     * @throws PeopleUnreachable
     */
    public function exchange(array $query, AuthorizationRequest $request): TokenSet
    {
        if (is_string($query['error'] ?? null)) {
            $description = is_string($query['error_description'] ?? null) ? $query['error_description'] : 'The sign-in was not completed.';

            throw new PeopleRefused($description, 400, $query['error']);
        }

        if (! is_string($query['state'] ?? null) || ! hash_equals($request->state, $query['state'])) {
            throw new TokenRejected('The callback answers another sign-in.');
        }

        if (! is_string($query['code'] ?? null) || $query['code'] === '') {
            throw new PeopleRefused('The callback carries no code.', 400, 'invalid_request');
        }

        $body = $this->http->form($this->discovery->endpoint('token_endpoint'), $this->credentials() + [
            'grant_type' => 'authorization_code',
            'code' => $query['code'],
            'redirect_uri' => $request->redirectUri,
            'code_verifier' => $request->codeVerifier,
        ]);

        return $this->tokens($body, $request->nonce);
    }

    /**
     * A fresh access token for a refresh token.
     *
     * @throws PeopleRefused when the refresh token is no longer good: sign them in again.
     * @throws PeopleUnreachable
     */
    public function refresh(string $refreshToken): TokenSet
    {
        $body = $this->http->form($this->discovery->endpoint('token_endpoint'), $this->credentials() + [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
        ]);

        return $this->tokens($body, null);
    }

    /**
     * Where to send somebody to sign out of People as well as here.
     *
     * `$returnTo` has to be one of this client's registered post-logout addresses.
     */
    public function signOutUrl(?string $idToken = null, ?string $returnTo = null, ?string $state = null): string
    {
        $query = array_filter([
            'client_id' => $this->config->clientId,
            'id_token_hint' => $idToken,
            'post_logout_redirect_uri' => $returnTo,
            'state' => $state,
        ], fn (?string $value): bool => $value !== null && $value !== '');

        return $this->discovery->endpoint('end_session_endpoint').($query === [] ? '' : '?'.http_build_query($query));
    }

    /** @return array<string, string> */
    private function credentials(): array
    {
        return ['client_id' => $this->config->clientId()] + (
            $this->config->clientSecret !== null && $this->config->clientSecret !== ''
                ? ['client_secret' => $this->config->clientSecret]
                : []
        );
    }

    /** @param  array<mixed>  $body */
    private function tokens(array $body, ?string $nonce): TokenSet
    {
        $tokens = TokenSet::from($body);

        if ($tokens->idToken === null) {
            return $tokens;
        }

        return TokenSet::from($body, $this->idTokens->verify($tokens->idToken, $nonce, $tokens->accessToken));
    }

    /** @param  positive-int  $bytes */
    private static function random(int $bytes = 32): string
    {
        return rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
    }

    private static function challenge(string $verifier): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    }
}

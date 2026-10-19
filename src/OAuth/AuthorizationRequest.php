<?php

declare(strict_types=1);

namespace Oki\People\OAuth;

/**
 * Where to send somebody to sign in, and what to keep until they come back.
 *
 * Keep `state`, `nonce` and `codeVerifier` server-side — in the session — and
 * hand them back to `Authorization::exchange()`. Never put the verifier in
 * the URL or a cookie the browser can read.
 */
final readonly class AuthorizationRequest
{
    public function __construct(
        public string $url,
        public string $state,
        public string $nonce,
        public string $codeVerifier,
        public string $redirectUri,
    ) {}
}

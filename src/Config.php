<?php

declare(strict_types=1);

namespace Oki\People;

use InvalidArgumentException;

/**
 * Who this application is to People, and where People is.
 *
 * Only `issuer` is required to verify tokens. Signing people in needs the
 * client id; anything a client does for itself — reading identity events —
 * needs its secret too.
 */
final readonly class Config
{
    /**
     * @param  string  $issuer  People's address, exactly as its discovery document names it: `https://people.example.com`.
     * @param  string|null  $clientId  This application's client id at People.
     * @param  string|null  $clientSecret  Its secret, for a confidential client. Never ship one to a browser.
     * @param  string|null  $audience  What this API is called in an access token's `aud` — its hostname, `api.example.com`. Null when it verifies no access tokens.
     * @param  int  $timeout  Seconds before a call to People is given up on.
     * @param  int  $keysTtl  Seconds a fetched key set or discovery document stays fresh.
     */
    public function __construct(
        public string $issuer,
        public ?string $clientId = null,
        public ?string $clientSecret = null,
        public ?string $audience = null,
        public int $timeout = 5,
        public int $keysTtl = 900,
    ) {
        if (! str_starts_with($issuer, 'https://') && ! str_starts_with($issuer, 'http://')) {
            throw new InvalidArgumentException('The issuer is People\'s address, starting https://.');
        }
    }

    /** The issuer with no trailing slash, which is how tokens carry it. */
    public function issuer(): string
    {
        return rtrim($this->issuer, '/');
    }

    /** @return non-empty-string */
    public function clientId(): string
    {
        return $this->clientId !== null && $this->clientId !== ''
            ? $this->clientId
            : throw new InvalidArgumentException('This needs a client id.');
    }

    /** @return non-empty-string */
    public function clientSecret(): string
    {
        return $this->clientSecret !== null && $this->clientSecret !== ''
            ? $this->clientSecret
            : throw new InvalidArgumentException('This needs a client secret: only a confidential client can do it.');
    }
}

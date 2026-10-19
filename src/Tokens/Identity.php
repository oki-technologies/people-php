<?php

declare(strict_types=1);

namespace Oki\People\Tokens;

use Oki\People\Exceptions\TokenRejected;

/**
 * Who signed in, as an `id_token` or userinfo tells it.
 *
 * Only what the granted scopes release is filled in: `profile` for the name
 * and picture, `email` for the address.
 */
final readonly class Identity
{
    /**
     * @param  non-empty-string  $subject  People's user id. The same for every application.
     * @param  array<string, mixed>  $claims  Every claim, for anything not given a name here.
     */
    public function __construct(
        public string $subject,
        public ?string $name = null,
        public ?string $username = null,
        public ?string $picture = null,
        public ?string $email = null,
        public bool $emailVerified = false,
        public array $claims = [],
    ) {}

    /**
     * @param  array<mixed>  $claims
     */
    public static function from(array $claims): self
    {
        $subject = $claims['sub'] ?? null;

        if (! is_string($subject) || $subject === '') {
            throw new TokenRejected('The identity names nobody.');
        }

        $text = fn (string $claim): ?string => is_string($claims[$claim] ?? null) && $claims[$claim] !== '' ? $claims[$claim] : null;

        /** @var array<string, mixed> $named */
        $named = array_filter($claims, is_string(...), ARRAY_FILTER_USE_KEY);

        return new self(
            subject: $subject,
            name: $text('name'),
            username: $text('preferred_username'),
            picture: $text('picture'),
            email: $text('email'),
            emailVerified: ($claims['email_verified'] ?? false) === true,
            claims: $named,
        );
    }
}

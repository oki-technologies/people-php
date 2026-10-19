<?php

declare(strict_types=1);

namespace Oki\People\Tokens;

use DateTimeImmutable;

/**
 * An access token that verified: who it is for, which client holds it, what it may do.
 *
 * Proof of identity, never of permission. What the subject may do here is
 * this application's to decide, against its own records.
 */
final readonly class AccessToken
{
    /**
     * @param  non-empty-string  $subject  People's user id — or the client's own id, for a token a client holds for itself.
     * @param  list<string>  $scopes
     * @param  list<string>  $audiences
     * @param  array<string, mixed>  $claims  Every claim, for anything not given a name here.
     */
    public function __construct(
        public string $jwt,
        public string $subject,
        public ?string $clientId,
        public array $scopes,
        public array $audiences,
        public DateTimeImmutable $expiresAt,
        public array $claims,
    ) {}

    /** Whether it was granted a scope. `*` is every scope. */
    public function can(string $scope): bool
    {
        return in_array('*', $this->scopes, true) || in_array($scope, $this->scopes, true);
    }

    /** Whether a client holds it for itself, with no person behind it. */
    public function isClientOnly(): bool
    {
        return $this->subject === $this->clientId;
    }
}

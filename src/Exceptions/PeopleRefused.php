<?php

declare(strict_types=1);

namespace Oki\People\Exceptions;

/**
 * People answered, and the answer was no.
 *
 * `$error` is the OAuth error code where there is one — `invalid_grant`,
 * `invalid_client` — and `$status` the HTTP status.
 */
final class PeopleRefused extends PeopleException
{
    public function __construct(
        string $message,
        public readonly int $status,
        public readonly ?string $error = null,
    ) {
        parent::__construct($message, $status);
    }
}

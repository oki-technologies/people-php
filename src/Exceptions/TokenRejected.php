<?php

declare(strict_types=1);

namespace Oki\People\Exceptions;

/**
 * A token that must not be trusted: forged, expired, or meant for somebody else.
 *
 * The message says which, for the log. Answer the caller with a plain 401.
 */
final class TokenRejected extends PeopleException {}

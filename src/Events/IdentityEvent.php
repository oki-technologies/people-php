<?php

declare(strict_types=1);

namespace Oki\People\Events;

use DateTimeImmutable;

/**
 * Something that happened to somebody who signed in to this application.
 *
 * Apply in `sequence` order. Delivery is at least once: the same `eventId`
 * can arrive twice, so applying one has to be safe to repeat.
 */
final readonly class IdentityEvent
{
    public const string REGISTERED = 'identity.registered';

    public const string UPDATED = 'identity.updated';

    public const string SUSPENDED = 'identity.suspended';

    public const string REINSTATED = 'identity.reinstated';

    /** The account is gone. Erase what is held about them. */
    public const string DELETED = 'identity.deleted';

    public const string PERSON_MERGED = 'identity.person_merged';

    public const string CREDENTIAL_CHANGED = 'identity.credential_changed';

    /**
     * @param  string  $subject  People's user id — the `sub` in their tokens.
     * @param  array<string, mixed>  $payload
     */
    public function __construct(
        public int $sequence,
        public string $eventId,
        public string $type,
        public string $subject,
        public array $payload,
        public DateTimeImmutable $occurredAt,
    ) {}

    /**
     * @param  array<mixed>  $event
     */
    public static function from(array $event): ?self
    {
        $occurred = is_string($event['occurred_at'] ?? null) ? date_create_immutable($event['occurred_at']) : false;
        $payload = is_array($event['payload'] ?? null) ? $event['payload'] : [];

        if (
            ! is_int($event['sequence'] ?? null)
            || ! is_string($event['event_id'] ?? null)
            || ! is_string($event['type'] ?? null)
            || ! is_string($event['subject_id'] ?? null)
            || $occurred === false
        ) {
            return null;
        }

        /** @var array<string, mixed> $named */
        $named = array_filter($payload, is_string(...), ARRAY_FILTER_USE_KEY);

        return new self($event['sequence'], $event['event_id'], $event['type'], $event['subject_id'], $named, $occurred);
    }
}

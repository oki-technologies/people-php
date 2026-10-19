<?php

declare(strict_types=1);

namespace Oki\People\Events;

/**
 * One page of identity events, oldest first.
 *
 * Store `next` once every event on the page is applied, and ask for what
 * comes after it. Null means this application is up to date: ask again later
 * from the same place.
 */
final readonly class EventPage
{
    /**
     * @param  list<IdentityEvent>  $events
     */
    public function __construct(
        public array $events,
        public ?int $next,
    ) {}
}

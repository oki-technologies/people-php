<?php

declare(strict_types=1);

use Oki\People\Events\IdentityEvent;
use Oki\People\Exceptions\PeopleRefused;

/** @return array<string, mixed> */
function event_body(int $sequence, string $type = IdentityEvent::UPDATED): array
{
    return [
        'sequence' => $sequence,
        'event_id' => "event-{$sequence}",
        'type' => $type,
        'subject_id' => 'user-1',
        'payload' => ['name' => 'Ada Lovelace'],
        'occurred_at' => '2026-10-19T09:00:00+00:00',
    ];
}

beforeEach(function () {
    $this->stage = stage();
    $this->stage->http->on('/oauth/token', ['access_token' => 'client-token', 'expires_in' => 900]);
});

it('reads a page of what happened, on the client\'s own token', function () {
    $this->stage->http->on('/v1/identity/events', ['data' => [event_body(4), event_body(7)], 'meta' => ['next' => 7]]);

    $page = $this->stage->people->identityEvents()->after(3, limit: 50);
    $asked = $this->stage->http->last('/v1/identity/events');

    expect($page->next)->toBe(7)
        ->and($page->events)->toHaveCount(2)
        ->and($page->events[0]->sequence)->toBe(4)
        ->and($page->events[0]->eventId)->toBe('event-4')
        ->and($page->events[0]->type)->toBe(IdentityEvent::UPDATED)
        ->and($page->events[0]->subject)->toBe('user-1')
        ->and($page->events[0]->payload)->toBe(['name' => 'Ada Lovelace'])
        ->and($page->events[0]->occurredAt->format('c'))->toBe('2026-10-19T09:00:00+00:00')
        ->and($asked?->getHeaderLine('Authorization'))->toBe('Bearer client-token')
        ->and($asked?->getUri()->getQuery())->toBe('after=3&limit=50')
        ->and(form_of($this->stage->http->last('/oauth/token'))['scope'])->toBe('identity.events');
});

it('says there is nothing to resume from once up to date', function () {
    $this->stage->http->on('/v1/identity/events', ['data' => [], 'meta' => ['next' => null]]);

    $page = $this->stage->people->identityEvents()->after(7);

    expect($page->events)->toBe([])
        ->and($page->next)->toBeNull();
});

it('passes over an entry that is not an event', function () {
    $this->stage->http->on('/v1/identity/events', ['data' => ['nonsense', ['sequence' => 'x'], event_body(5)], 'meta' => ['next' => 5]]);

    expect($this->stage->people->identityEvents()->after()->events)->toHaveCount(1);
});

it('tries once more on a fresh token when its held one is refused', function () {
    $this->stage->http->sequence('/v1/identity/events', [
        [401, ['message' => 'Unauthenticated.']],
        [200, ['data' => [event_body(1)], 'meta' => ['next' => 1]]],
    ]);

    expect($this->stage->people->identityEvents()->after()->events)->toHaveCount(1)
        ->and($this->stage->http->asked('/oauth/token'))->toBe(2);
});

it('gives up when a fresh token is refused too', function () {
    $this->stage->http->on('/v1/identity/events', ['message' => 'Unauthenticated.'], 401);

    $this->stage->people->identityEvents()->after();
})->throws(PeopleRefused::class);

it('does not retry a refusal that is not about the token', function () {
    $this->stage->http->on('/v1/identity/events', ['message' => 'This action is unauthorized.'], 403);

    try {
        $this->stage->people->identityEvents()->after();
    } catch (PeopleRefused) {
    }

    expect($this->stage->http->asked('/oauth/token'))->toBe(1);
});

<?php

declare(strict_types=1);

namespace Oki\People\Support;

use Oki\People\Exceptions\PeopleException;
use Psr\Clock\ClockInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * Something fetched from People, kept fresh for a while and kept after that.
 *
 * A stale copy stands while People cannot be reached: a key set or a
 * discovery document from fifteen minutes ago is far better than refusing
 * every request. Fetches are at most one per cooldown however many callers
 * ask, so a flood of requests naming unknown keys cannot become a flood of
 * requests to People.
 */
final readonly class Remembered
{
    public function __construct(
        private CacheInterface $cache,
        private ClockInterface $clock,
        private int $ttl,
        private int $cooldown = 60,
    ) {}

    /**
     * What is held, fetched again once stale or when asked to.
     *
     * @param  callable(): array<mixed>  $fetch  Throws a PeopleException when People cannot answer.
     * @return array<mixed>|null Null only when nothing was ever fetched.
     */
    public function get(string $key, callable $fetch, bool $refresh = false): ?array
    {
        /** @var mixed $held */
        $held = $this->cache->get($key);
        $held = is_array($held) && is_array($held['value'] ?? null) && is_int($held['fresh_until'] ?? null) ? $held : null;
        $now = $this->clock->now()->getTimestamp();

        if ($held !== null && ! $refresh && $held['fresh_until'] > $now) {
            return $held['value'];
        }

        if (! $this->mayAsk($key, $now)) {
            return $held['value'] ?? null;
        }

        try {
            $value = $fetch();
        } catch (PeopleException) {
            return $held['value'] ?? null;
        }

        $this->cache->set($key, ['value' => $value, 'fresh_until' => $now + $this->ttl]);

        return $value;
    }

    /** Whether a fetch may go out now, claiming the cooldown if it may. */
    private function mayAsk(string $key, int $now): bool
    {
        $asked = $key.'.asked';
        /** @var mixed $last */
        $last = $this->cache->get($asked);

        if (is_int($last) && $last + $this->cooldown > $now) {
            return false;
        }

        $this->cache->set($asked, $now, $this->cooldown);

        return true;
    }
}

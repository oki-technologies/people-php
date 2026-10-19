<?php

declare(strict_types=1);

namespace Oki\People\Tests\Support;

use DateInterval;
use Psr\SimpleCache\CacheInterface;

/** A PSR-16 cache in memory, on the suite's clock. */
final class ArrayCache implements CacheInterface
{
    /** @var array<string, array{mixed, int|null}> */
    private array $items = [];

    public function __construct(private readonly FrozenClock $clock) {}

    public function get(string $key, mixed $default = null): mixed
    {
        [$value, $until] = $this->items[$key] ?? [$default, null];

        if ($until !== null && $until <= $this->clock->now()->getTimestamp()) {
            unset($this->items[$key]);

            return $default;
        }

        return $value;
    }

    public function set(string $key, mixed $value, null|int|DateInterval $ttl = null): bool
    {
        $seconds = $ttl instanceof DateInterval ? (int) (new \DateTimeImmutable('@0'))->add($ttl)->format('U') : $ttl;
        $this->items[$key] = [$value, $seconds === null ? null : $this->clock->now()->getTimestamp() + $seconds];

        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->items[$key]);

        return true;
    }

    public function clear(): bool
    {
        $this->items = [];

        return true;
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        foreach ($keys as $key) {
            yield $key => $this->get($key, $default);
        }
    }

    /** @param  iterable<string, mixed>  $values */
    public function setMultiple(iterable $values, null|int|DateInterval $ttl = null): bool
    {
        foreach ($values as $key => $value) {
            $this->set($key, $value, $ttl);
        }

        return true;
    }

    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $key) {
            $this->delete($key);
        }

        return true;
    }

    public function has(string $key): bool
    {
        return $this->get($key, $this) !== $this;
    }
}

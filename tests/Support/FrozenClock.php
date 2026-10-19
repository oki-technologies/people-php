<?php

declare(strict_types=1);

namespace Oki\People\Tests\Support;

use DateTimeImmutable;
use Psr\Clock\ClockInterface;

/** Now, until a test moves it. */
final class FrozenClock implements ClockInterface
{
    private DateTimeImmutable $now;

    public function __construct()
    {
        $this->now = new DateTimeImmutable('@'.time());
    }

    public function now(): DateTimeImmutable
    {
        return $this->now;
    }

    public function travel(int $seconds): void
    {
        $this->now = $this->now->modify("+{$seconds} seconds");
    }
}

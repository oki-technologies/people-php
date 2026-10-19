<?php

declare(strict_types=1);

namespace Oki\People\Tests\Support;

use Nyholm\Psr7\Factory\Psr17Factory;
use Oki\People\Config;
use Oki\People\People;

/** The SDK, pointed at a fake People, with the doubles a test reaches for. */
final class Stage
{
    public readonly People $people;

    public function __construct(
        public readonly FakePeople $http,
        public readonly FrozenClock $clock,
        public readonly ArrayCache $cache,
        Config $config,
    ) {
        $factory = new Psr17Factory;
        $this->people = new People($config, $http, $factory, $factory, $cache, $clock);
    }
}

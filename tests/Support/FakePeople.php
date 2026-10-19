<?php

declare(strict_types=1);

namespace Oki\People\Tests\Support;

use Closure;
use Nyholm\Psr7\Response;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Client\NetworkExceptionInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;

/**
 * People, as far as the SDK can tell: a PSR-18 client answering by path.
 *
 * Every request is kept, so a test can say what was asked and how often.
 */
final class FakePeople implements ClientInterface
{
    /** @var array<string, list<Closure(RequestInterface): ResponseInterface>|Closure(RequestInterface): ResponseInterface> */
    private array $routes = [];

    /** @var list<RequestInterface> */
    public array $sent = [];

    /**
     * Answers a path with JSON — once per item when given a list of answers, the last repeating.
     *
     * @param  array<mixed>|list<array{int, array<mixed>}>|Closure(RequestInterface): ResponseInterface  $answer
     */
    public function on(string $path, array|Closure $answer, int $status = 200): self
    {
        $this->routes[$path] = $answer instanceof Closure
            ? $answer
            : fn (): ResponseInterface => self::json($answer, $status);

        return $this;
    }

    /**
     * Answers a path with each of these in turn, the last repeating.
     *
     * @param  list<array{int, array<mixed>}>  $answers
     */
    public function sequence(string $path, array $answers): self
    {
        $this->routes[$path] = array_map(
            fn (array $answer): Closure => fn (): ResponseInterface => self::json($answer[1], $answer[0]),
            $answers,
        );

        return $this;
    }

    /** Fails to connect for a path. */
    public function down(string $path): self
    {
        $this->routes[$path] = fn (RequestInterface $request): never => throw new class('Down.', $request) extends RuntimeException implements NetworkExceptionInterface
        {
            public function __construct(string $message, private readonly RequestInterface $request)
            {
                parent::__construct($message);
            }

            public function getRequest(): RequestInterface
            {
                return $this->request;
            }
        };

        return $this;
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->sent[] = $request;
        $path = $request->getUri()->getPath();
        $route = $this->routes[$path] ?? fn (): ResponseInterface => self::json(['message' => 'Not found.'], 404);

        if (is_array($route)) {
            $answer = count($route) > 1 ? array_shift($route) : $route[0];
            $this->routes[$path] = $route;

            return $answer($request);
        }

        return $route($request);
    }

    /** How many requests went to a path. */
    public function asked(string $path): int
    {
        return count(array_filter($this->sent, fn (RequestInterface $request): bool => $request->getUri()->getPath() === $path));
    }

    /** The last request to a path. */
    public function last(string $path): ?RequestInterface
    {
        $matching = array_values(array_filter($this->sent, fn (RequestInterface $request): bool => $request->getUri()->getPath() === $path));

        return $matching === [] ? null : $matching[count($matching) - 1];
    }

    /** @param  array<mixed>  $body */
    public static function json(array $body, int $status = 200): ResponseInterface
    {
        return new Response($status, ['Content-Type' => 'application/json'], (string) json_encode($body));
    }
}

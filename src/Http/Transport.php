<?php

declare(strict_types=1);

namespace Oki\People\Http;

use Oki\People\Exceptions\PeopleRefused;
use Oki\People\Exceptions\PeopleUnreachable;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

/**
 * JSON over whatever PSR-18 client the application already has.
 *
 * Every answer is either a decoded body or an exception that says which kind
 * of failure it was: People unreachable, or People saying no.
 */
final readonly class Transport
{
    public function __construct(
        private ClientInterface $client,
        private RequestFactoryInterface $requests,
        private StreamFactoryInterface $streams,
    ) {}

    /**
     * @param  array<string, string>  $headers
     * @return array<mixed>
     *
     * @throws PeopleUnreachable|PeopleRefused
     */
    public function get(string $url, array $headers = []): array
    {
        return $this->send('GET', $url, $headers);
    }

    /**
     * @param  array<string, string>  $fields
     * @param  array<string, string>  $headers
     * @return array<mixed>
     *
     * @throws PeopleUnreachable|PeopleRefused
     */
    public function form(string $url, array $fields, array $headers = []): array
    {
        return $this->send('POST', $url, ['Content-Type' => 'application/x-www-form-urlencoded'] + $headers, http_build_query($fields));
    }

    /**
     * @param  array<string, string>  $headers
     * @return array<mixed>
     */
    private function send(string $method, string $url, array $headers, ?string $body = null): array
    {
        $request = $this->requests->createRequest($method, $url)->withHeader('Accept', 'application/json');

        foreach ($headers as $name => $value) {
            $request = $request->withHeader($name, $value);
        }

        if ($body !== null) {
            $request = $request->withBody($this->streams->createStream($body));
        }

        try {
            $response = $this->client->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            throw new PeopleUnreachable("People could not be reached at {$url}.", previous: $e);
        }

        /** @var mixed $decoded */
        $decoded = json_decode((string) $response->getBody(), true);
        $status = $response->getStatusCode();

        if ($status >= 400 && $status < 500) {
            $said = fn (string $key): ?string => is_array($decoded) && is_string($decoded[$key] ?? null) ? $decoded[$key] : null;

            throw new PeopleRefused(
                $said('error_description') ?? $said('message') ?? "People refused the request with {$status}.",
                $status,
                $said('error'),
            );
        }

        if ($status >= 300 || ! is_array($decoded)) {
            throw new PeopleUnreachable("People answered {$url} with {$status} and no usable body.");
        }

        return $decoded;
    }
}

<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Token;

use Cline\JWT\Contracts\HeadersInterface;

use function array_key_exists;
use function is_string;

/**
 * Immutable read model over a decoded JOSE header segment.
 *
 * The header object preserves the original encoded segment while providing typed
 * helpers for the standard header names that participate in validation and token
 * reconstruction.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class Headers implements HeadersInterface
{
    /**
     * @param array<non-empty-string, mixed> $headers Decoded JOSE header map
     */
    public function __construct(
        private array $headers,
        private string $encoded,
    ) {}

    /**
     * Return a header value or the provided default when it is absent.
     */
    public function get(string $name, mixed $default = null): mixed
    {
        return $this->headers[$name] ?? $default;
    }

    /**
     * Return whether the header map contains the named key.
     */
    public function has(string $name): bool
    {
        return array_key_exists($name, $this->headers);
    }

    /**
     * Return the complete decoded header map.
     */
    public function all(): array
    {
        return $this->headers;
    }

    /**
     * Return the JOSE algorithm (`alg`) header when it is a string.
     */
    public function algorithm(): ?string
    {
        $algorithm = $this->get(RegisteredHeaders::ALGORITHM);

        return is_string($algorithm) ? $algorithm : null;
    }

    /**
     * Return the type (`typ`) header when it is a string.
     */
    public function type(): ?string
    {
        $type = $this->get(RegisteredHeaders::TYPE);

        return is_string($type) ? $type : null;
    }

    /**
     * Return the content-type (`cty`) header when it is a string.
     */
    public function contentType(): ?string
    {
        $contentType = $this->get(RegisteredHeaders::CONTENT_TYPE);

        return is_string($contentType) ? $contentType : null;
    }

    /**
     * Return the key identifier (`kid`) header when it is a string.
     */
    public function keyId(): ?string
    {
        $keyId = $this->get(RegisteredHeaders::KEY_ID);

        return is_string($keyId) ? $keyId : null;
    }

    /**
     * Return the original encoded JOSE header segment.
     */
    public function toString(): string
    {
        return $this->encoded;
    }
}

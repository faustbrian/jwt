<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Contracts;

/**
 * Read-only access contract for decoded JWT header values.
 *
 * Header implementations preserve the JOSE metadata that was parsed from the
 * token and expose both generic lookup methods and convenience accessors for
 * the standard header fields the package cares about during validation.
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface HeadersInterface
{
    /**
     * Retrieve a header value, returning the provided default when absent.
     *
     * @param non-empty-string $name
     */
    public function get(string $name, mixed $default = null): mixed;

    /**
     * Determine whether the named header is present.
     *
     * @param non-empty-string $name
     */
    public function has(string $name): bool;

    /**
     * Get all decoded header values as an associative array.
     *
     * @return array<non-empty-string, mixed>
     */
    public function all(): array;

    /**
     * Get the advertised JOSE algorithm identifier, if present.
     */
    public function algorithm(): ?string;

    /**
     * Get the token type (`typ`) header, if present.
     */
    public function type(): ?string;

    /**
     * Get the content type (`cty`) header, if present.
     */
    public function contentType(): ?string;

    /**
     * Get the key identifier (`kid`) header, if present.
     */
    public function keyId(): ?string;

    /**
     * Get the original base64url-encoded header segment.
     */
    public function toString(): string;
}

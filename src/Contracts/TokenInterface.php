<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Contracts;

use Carbon\CarbonInterface;
use NoDiscard;

/**
 * Read-only contract for parsed or issued JWTs.
 *
 * The token API exposes semantic helpers for the registered claims used by
 * validation constraints while still allowing callers to obtain the encoded token
 * string for transport or persistence.
 *
 * @immutable
 * @author Brian Faust <brian@cline.sh>
 */
interface TokenInterface
{
    /**
     * Return the token headers view.
     */
    public function headers(): HeadersInterface;

    /**
     * Return whether the token audience permits the given consumer.
     *
     * @param non-empty-string $audience
     */
    public function isPermittedFor(string $audience): bool;

    /**
     * Return whether the token JWT ID matches the expected identifier.
     *
     * @param non-empty-string $id
     */
    public function isIdentifiedBy(string $id): bool;

    /**
     * Return whether the token subject matches the expected value.
     *
     * @param non-empty-string $subject
     */
    public function isRelatedTo(string $subject): bool;

    /**
     * Return whether the token issuer matches any of the provided issuers.
     *
     * @param non-empty-string ...$issuers
     */
    public function hasBeenIssuedBy(string ...$issuers): bool;

    /**
     * Return whether the token issue time is at or before the supplied instant.
     */
    public function hasBeenIssuedBefore(CarbonInterface $now): bool;

    /**
     * Return whether the token is active by the supplied instant.
     */
    public function isMinimumTimeBefore(CarbonInterface $now): bool;

    /**
     * Return whether the token is expired at the supplied instant.
     */
    public function isExpired(CarbonInterface $now): bool;

    /**
     * Return the compact serialized representation of the token.
     *
     * @return non-empty-string
     */
    #[NoDiscard()]
    public function toString(): string;
}

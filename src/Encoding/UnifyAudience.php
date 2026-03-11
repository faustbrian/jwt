<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Encoding;

use Cline\JWT\Contracts\ClaimsFormatterInterface;
use Cline\JWT\Token\RegisteredClaims;

use function array_key_exists;
use function count;
use function current;
use function is_array;

/**
 * Claims formatter that collapses single-item audience arrays to a scalar.
 *
 * The JWT spec permits `aud` to be expressed either as a string or as an array
 * of strings. Internally the builder accumulates audiences as a list so callers
 * can append idempotently, and this formatter converts the one-item case back to
 * the compact scalar representation expected by many downstream consumers.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class UnifyAudience implements ClaimsFormatterInterface
{
    /**
     * Collapse a single audience entry to a scalar while preserving multi-value
     * audiences as arrays.
     */
    public function formatClaims(array $claims): array
    {
        if (
            !array_key_exists(RegisteredClaims::AUDIENCE, $claims)
            || !is_array($claims[RegisteredClaims::AUDIENCE])
            || count($claims[RegisteredClaims::AUDIENCE]) !== 1
        ) {
            return $claims;
        }

        $claims[RegisteredClaims::AUDIENCE] = current($claims[RegisteredClaims::AUDIENCE]);

        return $claims;
    }
}

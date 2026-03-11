<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Contracts;

use NoDiscard;

/**
 * Normalizes claim values before they are JSON encoded into a token payload.
 *
 * Formatters are the last transformation stage before claims are serialized.
 * They allow the package to convert rich PHP values, such as Carbon instances
 * or audience shortcuts, into RFC-compatible scalar or array structures without
 * forcing callers to pre-normalize every value manually.
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface ClaimsFormatterInterface
{
    /**
     * Format the claim map into the JSON-ready structure that will be encoded.
     *
     * Implementations may replace values, add normalization for registered
     * claims, or preserve unknown claims unchanged, but they should not mutate
     * the caller's original array in place.
     *
     * @param array<non-empty-string, mixed> $claims
     *
     * @return array<non-empty-string, mixed>
     */
    #[NoDiscard()]
    public function formatClaims(array $claims): array;
}

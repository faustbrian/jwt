<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Encoding;

use Carbon\CarbonInterface;
use Cline\JWT\Contracts\ClaimsFormatterInterface;
use Cline\JWT\Token\RegisteredClaims;

use function array_key_exists;

/**
 * Claims formatter that preserves sub-second precision for registered date
 * claims whenever the source value carries microseconds.
 *
 * JWT date claims are commonly represented as integer timestamps, but some
 * systems need fractional precision for issued-at or expiry comparisons. This
 * formatter keeps integer output for whole-second values and emits floats only
 * when microseconds are actually present.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class MicrosecondBasedDateConversion implements ClaimsFormatterInterface
{
    /**
     * Normalize registered date claims to integer or fractional UNIX timestamps.
     *
     * Only the standard JWT date claims are inspected. Non-date claims and
     * already-normalized scalar values are passed through unchanged.
     */
    public function formatClaims(array $claims): array
    {
        foreach (RegisteredClaims::DATE_CLAIMS as $claim) {
            if (!array_key_exists($claim, $claims)) {
                continue;
            }

            if (!$claims[$claim] instanceof CarbonInterface) {
                continue;
            }

            $claims[$claim] = $this->convertDate($claims[$claim]);
        }

        return $claims;
    }

    /**
     * Convert a Carbon date to the narrowest timestamp representation that
     * preserves the original precision.
     */
    private function convertDate(CarbonInterface $date): int|float
    {
        if ($date->format('u') === '000000') {
            return (int) $date->format('U');
        }

        return (float) $date->format('U.u');
    }
}

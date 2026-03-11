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
 * Claims formatter that normalizes registered date claims to integer UNIX timestamps.
 *
 * This formatter is used when producing interoperable compact tokens for consumers
 * that expect the conventional whole-second JWT date representation.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class UnixTimestampDates implements ClaimsFormatterInterface
{
    /**
     * Normalize registered date claims to integer UNIX timestamps.
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
     * Convert a Carbon date into its whole-second UNIX timestamp.
     */
    private function convertDate(CarbonInterface $date): int
    {
        return $date->getTimestamp();
    }
}

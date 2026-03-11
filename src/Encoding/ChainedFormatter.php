<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Encoding;

use Cline\JWT\Contracts\ClaimsFormatterInterface;

/**
 * Claims formatter that runs several formatting passes in a deterministic order.
 *
 * Formatter order matters because one pass may change the shape expected by the
 * next. The built-in factories encode the package's canonical ordering for
 * audience normalization and date conversion.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class ChainedFormatter implements ClaimsFormatterInterface
{
    /** @var array<ClaimsFormatterInterface> */
    private array $formatters;

    /**
     * @param ClaimsFormatterInterface ...$formatters Ordered formatters applied left to right
     */
    public function __construct(ClaimsFormatterInterface ...$formatters)
    {
        $this->formatters = $formatters;
    }

    /**
     * Create the default formatter chain used by most builders.
     */
    public static function default(): self
    {
        return new self(
            new UnifyAudience(),
            new MicrosecondBasedDateConversion(),
        );
    }

    /**
     * Create the formatter chain used when emitting classic integer JWT dates.
     */
    public static function withUnixTimestampDates(): self
    {
        return new self(
            new UnifyAudience(),
            new UnixTimestampDates(),
        );
    }

    /**
     * Apply every formatter in order, feeding each pass the previous result.
     */
    public function formatClaims(array $claims): array
    {
        foreach ($this->formatters as $formatter) {
            $claims = $formatter->formatClaims($claims);
        }

        return $claims;
    }
}

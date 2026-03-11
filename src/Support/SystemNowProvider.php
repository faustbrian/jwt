<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Support;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Cline\JWT\Contracts\NowProviderInterface;

/**
 * Production clock implementation backed by CarbonImmutable::now().
 *
 * The abstraction allows validators and issuers to depend on a clock contract
 * while tests substitute deterministic time sources.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class SystemNowProvider implements NowProviderInterface
{
    /**
     * Return the current wall-clock instant as an immutable Carbon instance.
     */
    public function now(): CarbonInterface
    {
        return CarbonImmutable::now();
    }
}

<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Contracts;

use Carbon\CarbonInterface;

/**
 * Time source used when issuing or validating tokens.
 *
 * Pulling "now" behind a contract makes issuance and validation deterministic
 * in tests and allows applications to centralize clock strategy without wiring
 * Carbon instances through every call site.
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface NowProviderInterface
{
    /**
     * Return the current instant used for token lifecycle decisions.
     */
    public function now(): CarbonInterface;
}

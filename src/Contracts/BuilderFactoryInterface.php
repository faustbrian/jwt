<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Contracts;

/**
 * Factory for issuing fresh immutable token builders.
 *
 * The runtime configuration keeps a builder factory instead of a concrete
 * builder so each issuance flow starts from a clean state while still allowing
 * applications to swap the builder implementation or preset dependencies.
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface BuilderFactoryInterface
{
    /**
     * Create a new builder configured with the claim formatter for this run.
     *
     * The formatter determines how claim values are normalized immediately before
     * encoding, so callers can vary serialization strategy without changing the
     * builder implementation itself.
     */
    public function create(ClaimsFormatterInterface $claimsFormatter): BuilderInterface;
}

<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Support;

use Cline\JWT\Contracts\BuilderFactoryInterface;
use Cline\JWT\Contracts\BuilderInterface;
use Cline\JWT\Contracts\ClaimsFormatterInterface;
use Cline\JWT\Contracts\EncoderInterface;
use Cline\JWT\Token\Builder;

/**
 * Default builder factory that creates immutable token builders with a shared encoder.
 *
 * The factory exists so runtime configuration can swap builder creation strategies
 * without coupling consumers to the concrete Builder implementation.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class DefaultBuilderFactory implements BuilderFactoryInterface
{
    /**
     * @param EncoderInterface $encoder Encoder used for JSON and base64url operations
     */
    public function __construct(
        private EncoderInterface $encoder,
    ) {}

    /**
     * Create a new builder that will format claims using the provided formatter.
     */
    public function create(ClaimsFormatterInterface $claimsFormatter): BuilderInterface
    {
        return Builder::new($this->encoder, $claimsFormatter);
    }
}

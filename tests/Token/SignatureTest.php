<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Token;

use Cline\JWT\Token\Signature;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * @author Brian Faust <brian@cline.sh>
 * @internal
 */
#[CoversClass(Signature::class)]
final class SignatureTest extends TestCase
{
    #[Test()]
    public function hash_should_return_the_hash(): void
    {
        $signature = new Signature('test', 'encoded');

        $this->assertSame('test', $signature->hash());
        $this->assertSame('encoded', $signature->toString());
    }
}

<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Token;

use Carbon\CarbonImmutable;
use Cline\JWT\Token\Claims;
use Cline\JWT\Token\Headers;
use Cline\JWT\Token\RegisteredClaims;
use Cline\JWT\Token\RegisteredHeaders;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * @author Brian Faust <brian@cline.sh>
 * @internal
 */
#[CoversClass(Claims::class)]
#[CoversClass(Headers::class)]
final class TokenSectionsTest extends TestCase
{
    #[Test()]
    public function claims_get_should_return_the_configured_value(): void
    {
        $set = new Claims(['one' => 1], 'one=1');

        $this->assertSame(1, $set->get('one'));
    }

    #[Test()]
    public function headers_get_should_return_the_fallback_value_when_it_was_given(): void
    {
        $set = new Headers(['one' => 1], 'one=1');

        $this->assertSame(2, $set->get('two', 2));
    }

    #[Test()]
    public function claims_get_should_return_null_when_fallback_value_was_not_given(): void
    {
        $set = new Claims(['one' => 1], 'one=1');

        $this->assertNull($set->get('two'));
    }

    #[Test()]
    public function headers_has_should_return_true_when_item_was_configured(): void
    {
        $set = new Headers(['one' => 1], 'one=1');

        $this->assertTrue($set->has('one'));
    }

    #[Test()]
    public function claims_has_should_return_false_when_item_was_not_configured(): void
    {
        $set = new Claims(['one' => 1], 'one=1');

        $this->assertFalse($set->has('two'));
    }

    #[Test()]
    public function headers_all_should_return_all_configured_items(): void
    {
        $items = ['one' => 1, 'two' => 2];
        $set = new Headers($items, 'one=1');

        $this->assertSame($items, $set->all());
    }

    #[Test()]
    public function claims_to_string_should_return_the_encoded_data(): void
    {
        $set = new Claims(['one' => 1], 'one=1');

        $this->assertSame('one=1', $set->toString());
    }

    #[Test()]
    public function claims_expose_registered_claim_accessors(): void
    {
        $issuedAt = CarbonImmutable::parse('2024-01-01 00:00:00');
        $notBefore = $issuedAt->addMinute();
        $expiresAt = $issuedAt->addHour();
        $set = new Claims([
            RegisteredClaims::AUDIENCE => ['web', 'admin'],
            RegisteredClaims::ISSUER => 'https://api.example.test',
            RegisteredClaims::SUBJECT => 'user-1',
            RegisteredClaims::ID => 'token-1',
            RegisteredClaims::ISSUED_AT => $issuedAt,
            RegisteredClaims::NOT_BEFORE => $notBefore,
            RegisteredClaims::EXPIRATION_TIME => $expiresAt,
        ], 'claims');

        $this->assertSame(['web', 'admin'], $set->audiences());
        $this->assertSame('https://api.example.test', $set->issuer());
        $this->assertSame('user-1', $set->subject());
        $this->assertSame('token-1', $set->identifier());
        $this->assertSame($issuedAt, $set->issuedAt());
        $this->assertSame($notBefore, $set->notBefore());
        $this->assertSame($expiresAt, $set->expiresAt());
    }

    #[Test()]
    public function headers_expose_registered_header_accessors(): void
    {
        $set = new Headers([
            RegisteredHeaders::ALGORITHM => 'HS256',
            RegisteredHeaders::TYPE => 'JWT',
            RegisteredHeaders::CONTENT_TYPE => 'json',
            RegisteredHeaders::KEY_ID => 'key-1',
        ], 'headers');

        $this->assertSame('HS256', $set->algorithm());
        $this->assertSame('JWT', $set->type());
        $this->assertSame('json', $set->contentType());
        $this->assertSame('key-1', $set->keyId());
    }
}

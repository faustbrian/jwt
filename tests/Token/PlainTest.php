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
use Cline\JWT\Token\Plain;
use Cline\JWT\Token\RegisteredClaims;
use Cline\JWT\Token\Signature;
use PHPUnit\Framework\Attributes\Before;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * @author Brian Faust <brian@cline.sh>
 * @internal
 */
#[CoversClass(Plain::class)]
#[UsesClass(Claims::class)]
#[UsesClass(Headers::class)]
#[UsesClass(Signature::class)]
final class PlainTest extends TestCase
{
    private Headers $headers;

    private Claims $claims;

    private Signature $signature;

    #[Before()]
    public function createDependencies(): void
    {
        $this->headers = new Headers(['alg' => 'none'], 'headers');
        $this->claims = new Claims([], 'claims');
        $this->signature = new Signature('hash', 'signature');
    }

    #[Test()]
    public function signed_should_create_a_token_with_signature(): void
    {
        $token = $this->createToken();

        $this->assertSame($this->headers, $token->headers());
        $this->assertSame($this->claims, $token->claims());
        $this->assertSame($this->signature, $token->signature());
    }

    #[Test()]
    public function payload_should_return_a_string_with_the_encoded_headers_and_claims(): void
    {
        $token = $this->createToken();

        $this->assertSame('headers.claims', $token->payload());
    }

    #[Test()]
    public function is_permitted_for_should_return_false_when_no_audience_is_configured(): void
    {
        $token = $this->createToken();

        $this->assertFalse($token->isPermittedFor('testing'));
    }

    #[Test()]
    public function is_permitted_for_should_return_false_when_audience_does_not_match_as_array(): void
    {
        $token = $this->createToken(
            null,
            new Claims([RegisteredClaims::AUDIENCE => ['test', 'test2']], ''),
        );

        $this->assertFalse($token->isPermittedFor('testing'));
    }

    #[Test()]
    public function is_permitted_for_should_return_false_when_audience_type_does_not_match(): void
    {
        $token = $this->createToken(
            null,
            new Claims([RegisteredClaims::AUDIENCE => [10]], ''),
        );

        $this->assertFalse($token->isPermittedFor('10'));
    }

    #[Test()]
    public function is_permitted_for_should_return_true_when_audience_matches_as_array(): void
    {
        $token = $this->createToken(
            null,
            new Claims([RegisteredClaims::AUDIENCE => ['testing', 'test']], ''),
        );

        $this->assertTrue($token->isPermittedFor('testing'));
    }

    #[Test()]
    public function is_identified_by_should_return_false_when_no_id_was_configured(): void
    {
        $token = $this->createToken();

        $this->assertFalse($token->isIdentifiedBy('test'));
    }

    #[Test()]
    public function is_identified_by_should_return_false_when_id_does_not_match(): void
    {
        $token = $this->createToken(
            null,
            new Claims([RegisteredClaims::ID => 'testing'], ''),
        );

        $this->assertFalse($token->isIdentifiedBy('test'));
    }

    #[Test()]
    public function is_identified_by_should_return_true_when_id_matches(): void
    {
        $token = $this->createToken(
            null,
            new Claims([RegisteredClaims::ID => 'test'], ''),
        );

        $this->assertTrue($token->isIdentifiedBy('test'));
    }

    #[Test()]
    public function is_related_to_should_return_false_when_no_subject_was_configured(): void
    {
        $token = $this->createToken();

        $this->assertFalse($token->isRelatedTo('test'));
    }

    #[Test()]
    public function is_related_to_should_return_false_when_subject_does_not_match(): void
    {
        $token = $this->createToken(
            null,
            new Claims([RegisteredClaims::SUBJECT => 'testing'], ''),
        );

        $this->assertFalse($token->isRelatedTo('test'));
    }

    #[Test()]
    public function is_related_to_should_return_true_when_subject_matches(): void
    {
        $token = $this->createToken(
            null,
            new Claims([RegisteredClaims::SUBJECT => 'test'], ''),
        );

        $this->assertTrue($token->isRelatedTo('test'));
    }

    #[Test()]
    public function has_been_issued_by_should_return_false_when_issuer_is_not_configured(): void
    {
        $token = $this->createToken();

        $this->assertFalse($token->hasBeenIssuedBy('test'));
    }

    #[Test()]
    public function has_been_issued_by_should_return_false_when_issuer_type_does_not_matches(): void
    {
        $token = $this->createToken(
            null,
            new Claims([RegisteredClaims::ISSUER => 10], ''),
        );

        $this->assertFalse($token->hasBeenIssuedBy('10'));
    }

    #[Test()]
    public function has_been_issued_by_should_return_false_when_issuer_is_not_in_the_given_list(): void
    {
        $token = $this->createToken(
            null,
            new Claims([RegisteredClaims::ISSUER => 'test'], ''),
        );

        $this->assertFalse($token->hasBeenIssuedBy('testing1', 'testing2'));
    }

    #[Test()]
    public function has_been_issued_by_should_return_true_when_issuer_is_in_the_given_list(): void
    {
        $token = $this->createToken(
            null,
            new Claims([RegisteredClaims::ISSUER => 'test'], ''),
        );

        $this->assertTrue($token->hasBeenIssuedBy('testing1', 'testing2', 'test'));
    }

    #[Test()]
    public function has_been_issued_before_should_return_true_when_issue_time_is_not_configured(): void
    {
        $token = $this->createToken();

        $this->assertTrue($token->hasBeenIssuedBefore(CarbonImmutable::now()));
    }

    #[Test()]
    public function has_been_issued_before_should_return_true_when_issue_time_is_before_than_now(): void
    {
        $now = CarbonImmutable::now();
        $token = $this->createToken(
            null,
            new Claims([RegisteredClaims::ISSUED_AT => $now->modify('-100 seconds')], ''),
        );

        $this->assertTrue($token->hasBeenIssuedBefore($now));
    }

    #[Test()]
    public function has_been_issued_before_should_return_true_when_issue_time_is_equals_to_now(): void
    {
        $now = CarbonImmutable::now();
        $token = $this->createToken(
            null,
            new Claims([RegisteredClaims::ISSUED_AT => $now], ''),
        );

        $this->assertTrue($token->hasBeenIssuedBefore($now));
    }

    #[Test()]
    public function has_been_issued_before_should_return_false_when_issue_time_is_greater_than_now(): void
    {
        $now = CarbonImmutable::now();
        $token = $this->createToken(
            null,
            new Claims([RegisteredClaims::ISSUED_AT => $now->modify('+100 seconds')], ''),
        );

        $this->assertFalse($token->hasBeenIssuedBefore($now));
    }

    #[Test()]
    public function is_minimum_time_before_should_return_true_when_issue_time_is_not_configured(): void
    {
        $token = $this->createToken();

        $this->assertTrue($token->isMinimumTimeBefore(CarbonImmutable::now()));
    }

    #[Test()]
    public function is_minimum_time_before_should_return_true_when_not_before_claim_is_before_than_now(): void
    {
        $now = CarbonImmutable::now();
        $token = $this->createToken(
            null,
            new Claims([RegisteredClaims::NOT_BEFORE => $now->modify('-100 seconds')], ''),
        );

        $this->assertTrue($token->isMinimumTimeBefore($now));
    }

    #[Test()]
    public function is_minimum_time_before_should_return_true_when_not_before_claim_is_equals_to_now(): void
    {
        $now = CarbonImmutable::now();
        $token = $this->createToken(
            null,
            new Claims([RegisteredClaims::NOT_BEFORE => $now], ''),
        );

        $this->assertTrue($token->isMinimumTimeBefore($now));
    }

    #[Test()]
    public function is_minimum_time_before_should_return_false_when_not_before_claim_is_greater_than_now(): void
    {
        $now = CarbonImmutable::now();
        $token = $this->createToken(
            null,
            new Claims([RegisteredClaims::NOT_BEFORE => $now->modify('100 seconds')], ''),
        );

        $this->assertFalse($token->isMinimumTimeBefore($now));
    }

    #[Test()]
    public function is_expired_should_return_false_when_token_does_not_expires(): void
    {
        $token = $this->createToken();

        $this->assertFalse($token->isExpired(CarbonImmutable::now()));
    }

    #[Test()]
    public function is_expired_should_return_false_when_token_is_not_expired(): void
    {
        $now = CarbonImmutable::now();

        $token = $this->createToken(
            null,
            new Claims([RegisteredClaims::EXPIRATION_TIME => $now->modify('+500 seconds')], ''),
        );

        $this->assertFalse($token->isExpired($now));
    }

    #[Test()]
    public function is_expired_should_return_true_when_expiration_is_equals_to_now(): void
    {
        $now = CarbonImmutable::now();

        $token = $this->createToken(
            null,
            new Claims([RegisteredClaims::EXPIRATION_TIME => $now], ''),
        );

        $this->assertTrue($token->isExpired($now));
    }

    #[Test()]
    public function is_expired_should_return_true_after_token_expires(): void
    {
        $now = CarbonImmutable::now();

        $token = $this->createToken(
            null,
            new Claims([RegisteredClaims::EXPIRATION_TIME => $now], ''),
        );

        $this->assertTrue($token->isExpired($now->modify('+10 days')));
    }

    #[Test()]
    public function to_string_must_return_encoded_data_with_empty_signature(): void
    {
        $token = $this->createToken(null, null, new Signature('123', '456'));

        $this->assertSame('headers.claims.456', $token->toString());
    }

    #[Test()]
    public function to_string_must_return_encoded_data(): void
    {
        $token = $this->createToken();

        $this->assertSame('headers.claims.signature', $token->toString());
    }

    private function createToken(
        ?Headers $headers = null,
        ?Claims $claims = null,
        ?Signature $signature = null,
    ): Plain {
        return new Plain(
            $headers ?? $this->headers,
            $claims ?? $this->claims,
            $signature ?? $this->signature,
        );
    }
}

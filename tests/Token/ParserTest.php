<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Token;

use Carbon\CarbonImmutable;
use Cline\JWT\Contracts\DecoderInterface;
use Cline\JWT\Exceptions\InvalidTokenStructure;
use Cline\JWT\Exceptions\UnsupportedHeaderFound;
use Cline\JWT\Token\Claims;
use Cline\JWT\Token\Headers;
use Cline\JWT\Token\Parser;
use Cline\JWT\Token\Plain;
use Cline\JWT\Token\RegisteredClaims;
use Cline\JWT\Token\Signature;
use PHPUnit\Framework\Attributes\Before;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * @author Brian Faust <brian@cline.sh>
 * @internal
 */
#[CoversClass(Parser::class)]
#[CoversClass(InvalidTokenStructure::class)]
#[CoversClass(UnsupportedHeaderFound::class)]
#[UsesClass(Plain::class)]
#[UsesClass(Claims::class)]
#[UsesClass(Headers::class)]
#[UsesClass(Signature::class)]
final class ParserTest extends TestCase
{
    private DecoderInterface&MockObject $decoder;

    #[Before()]
    public function createDependencies(): void
    {
        $this->decoder = $this->createMock(DecoderInterface::class);
    }

    #[Test()]
    public function parse_must_raise_exception_when_token_does_not_have_three_parts(): void
    {
        $this->decoder->expects($this->never())->method($this->anything());

        $parser = $this->createParser();

        $this->expectException(InvalidTokenStructure::class);
        $this->expectExceptionMessage('The JWT string must have two dots');

        $parser->parse('.');
    }

    #[Test()]
    public function parse_must_raise_exception_when_token_does_not_have_headers(): void
    {
        $this->decoder->expects($this->never())->method($this->anything());

        $parser = $this->createParser();

        $this->expectException(InvalidTokenStructure::class);
        $this->expectExceptionMessage('The JWT string is missing the Header part');

        $parser->parse('.b.c');
    }

    #[Test()]
    public function parse_must_raise_exception_when_token_does_not_have_claims(): void
    {
        $this->decoder->expects($this->never())->method($this->anything());

        $parser = $this->createParser();

        $this->expectException(InvalidTokenStructure::class);
        $this->expectExceptionMessage('The JWT string is missing the Claim part');

        $parser->parse('a..c');
    }

    #[Test()]
    public function parse_must_raise_exception_when_token_does_not_have_signature(): void
    {
        $this->decoder->expects($this->never())->method($this->anything());

        $parser = $this->createParser();

        $this->expectException(InvalidTokenStructure::class);
        $this->expectExceptionMessage('The JWT string is missing the Signature part');

        $parser->parse('a.b.');
    }

    #[Test()]
    public function parse_must_raise_exception_when_header_cannot_be_decoded(): void
    {
        $this->decoder
            ->expects($this->once())
            ->method('base64UrlDecode')
            ->with('a')
            ->willReturn('b');

        $this->decoder
            ->expects($this->once())
            ->method('jsonDecode')
            ->with('b')
            ->willThrowException(
                new RuntimeException('Nope'),
            );

        $parser = $this->createParser();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Nope');

        $parser->parse('a.b.c');
    }

    #[Test()]
    public function parse_must_raise_exception_when_dealing_with_non_array_headers(): void
    {
        $this->decoder->expects($this->once())
            ->method('jsonDecode')
            ->willReturn('A very invalid header');

        $parser = $this->createParser();

        $this->expectException(InvalidTokenStructure::class);
        $this->expectExceptionMessage('headers must be an array');

        $parser->parse('a.a.a');
    }

    #[Test()]
    public function parse_must_raise_exception_when_dealing_with_headers_that_have_empty_string_keys(): void
    {
        $this->decoder->expects($this->once())
            ->method('jsonDecode')
            ->willReturn(['' => 'foo']);

        $parser = $this->createParser();

        $this->expectException(InvalidTokenStructure::class);
        $this->expectExceptionMessage('headers must be an array');

        $parser->parse('a.a.a');
    }

    #[Test()]
    public function parse_must_raise_exception_when_header_is_from_an_encrypted_token(): void
    {
        $this->decoder->expects($this->once())
            ->method('jsonDecode')
            ->willReturn(['enc' => 'AAA']);

        $parser = $this->createParser();

        $this->expectException(UnsupportedHeaderFound::class);
        $this->expectExceptionMessage('Encryption is not supported yet');

        $parser->parse('a.a.a');
    }

    #[Test()]
    public function parse_must_raise_exception_when_dealing_with_non_array_claims(): void
    {
        $this->decoder->expects($this->exactly(2))
            ->method('jsonDecode')
            ->willReturnOnConsecutiveCalls(['typ' => 'JWT'], 'A very invalid claim set');

        $parser = $this->createParser();

        $this->expectException(InvalidTokenStructure::class);
        $this->expectExceptionMessage('claims must be an array');

        $parser->parse('a.a.a');
    }

    #[Test()]
    public function parse_must_raise_exception_when_dealing_with_claims_that_have_empty_string_keys(): void
    {
        $this->decoder->expects($this->exactly(2))
            ->method('jsonDecode')
            ->willReturnOnConsecutiveCalls(['typ' => 'JWT'], ['' => 'foo']);

        $parser = $this->createParser();

        $this->expectException(InvalidTokenStructure::class);
        $this->expectExceptionMessage('claims must be an array');

        $parser->parse('a.a.a');
    }

    #[Test()]
    public function parse_must_return_an_unsecured_token_when_signature_is_not_informed(): void
    {
        $this->decoder->expects($this->exactly(3))
            ->method('base64UrlDecode')
            ->willReturnMap([
                ['a', 'a_dec'],
                ['b', 'b_dec'],
                ['c', 'c_dec'],
            ]);

        $this->decoder->expects($this->exactly(2))
            ->method('jsonDecode')
            ->willReturnMap([
                ['a_dec', ['typ' => 'JWT', 'alg' => 'none']],
                ['b_dec', [RegisteredClaims::AUDIENCE => 'test']],
            ]);

        $parser = $this->createParser();
        $token = $parser->parse('a.b.c');

        $this->assertInstanceOf(Plain::class, $token);

        $headers = new Headers(['typ' => 'JWT', 'alg' => 'none'], 'a');
        $claims = new Claims([RegisteredClaims::AUDIENCE => ['test']], 'b');
        $signature = new Signature('c_dec', 'c');

        $this->assertEquals($headers, $token->headers());
        $this->assertEquals($claims, $token->claims());
        $this->assertEquals($signature, $token->signature());
    }

    #[Test()]
    public function parse_must_configure_type_to_jwt_when_it_is_missing(): void
    {
        $this->decoder->expects($this->exactly(3))
            ->method('base64UrlDecode')
            ->willReturnMap([
                ['a', 'a_dec'],
                ['b', 'b_dec'],
                ['c', 'c_dec'],
            ]);

        $this->decoder->expects($this->exactly(2))
            ->method('jsonDecode')
            ->willReturnMap([
                ['a_dec', ['alg' => 'none']],
                ['b_dec', [RegisteredClaims::AUDIENCE => 'test']],
            ]);

        $parser = $this->createParser();
        $token = $parser->parse('a.b.c');

        $this->assertInstanceOf(Plain::class, $token);

        $headers = new Headers(['typ' => 'JWT', 'alg' => 'none'], 'a');
        $claims = new Claims([RegisteredClaims::AUDIENCE => ['test']], 'b');
        $signature = new Signature('c_dec', 'c');

        $this->assertEquals($headers, $token->headers());
        $this->assertEquals($claims, $token->claims());
        $this->assertEquals($signature, $token->signature());
    }

    #[Test()]
    public function parse_must_not_change_type_when_it_is_configured(): void
    {
        $this->decoder->expects($this->exactly(3))
            ->method('base64UrlDecode')
            ->willReturnMap([
                ['a', 'a_dec'],
                ['b', 'b_dec'],
                ['c', 'c_dec'],
            ]);

        $this->decoder->expects($this->exactly(2))
            ->method('jsonDecode')
            ->willReturnMap([
                ['a_dec', ['typ' => 'JWS', 'alg' => 'none']],
                ['b_dec', [RegisteredClaims::AUDIENCE => 'test']],
            ]);

        $parser = $this->createParser();
        $token = $parser->parse('a.b.c');

        $this->assertInstanceOf(Plain::class, $token);

        $headers = new Headers(['typ' => 'JWS', 'alg' => 'none'], 'a');
        $claims = new Claims([RegisteredClaims::AUDIENCE => ['test']], 'b');
        $signature = new Signature('c_dec', 'c');

        $this->assertEquals($headers, $token->headers());
        $this->assertEquals($claims, $token->claims());
        $this->assertEquals($signature, $token->signature());
    }

    #[Test()]
    public function parse_should_replicate_claim_value_on_header_when_needed(): void
    {
        $this->decoder->expects($this->exactly(3))
            ->method('base64UrlDecode')
            ->willReturnMap([
                ['a', 'a_dec'],
                ['b', 'b_dec'],
                ['c', 'c_dec'],
            ]);

        $this->decoder->expects($this->exactly(2))
            ->method('jsonDecode')
            ->willReturnMap([
                ['a_dec', ['typ' => 'JWT', 'alg' => 'none', RegisteredClaims::AUDIENCE => 'test']],
                ['b_dec', [RegisteredClaims::AUDIENCE => 'test']],
            ]);

        $parser = $this->createParser();
        $token = $parser->parse('a.b.c');

        $this->assertInstanceOf(Plain::class, $token);

        $headers = new Headers(['typ' => 'JWT', 'alg' => 'none', RegisteredClaims::AUDIENCE => 'test'], 'a');
        $claims = new Claims([RegisteredClaims::AUDIENCE => ['test']], 'b');
        $signature = new Signature('c_dec', 'c');

        $this->assertEquals($headers, $token->headers());
        $this->assertEquals($claims, $token->claims());
        $this->assertEquals($signature, $token->signature());
    }

    #[Test()]
    public function parse_must_return_a_non_signed_token_when_signature_algorithm_is_missing(): void
    {
        $this->decoder->expects($this->exactly(3))
            ->method('base64UrlDecode')
            ->willReturnMap([
                ['a', 'a_dec'],
                ['b', 'b_dec'],
                ['c', 'c_dec'],
            ]);

        $this->decoder->expects($this->exactly(2))
            ->method('jsonDecode')
            ->willReturnMap([
                ['a_dec', ['typ' => 'JWT']],
                ['b_dec', [RegisteredClaims::AUDIENCE => 'test']],
            ]);

        $parser = $this->createParser();
        $token = $parser->parse('a.b.c');

        $this->assertInstanceOf(Plain::class, $token);

        $headers = new Headers(['typ' => 'JWT'], 'a');
        $claims = new Claims([RegisteredClaims::AUDIENCE => ['test']], 'b');
        $signature = new Signature('c_dec', 'c');

        $this->assertEquals($headers, $token->headers());
        $this->assertEquals($claims, $token->claims());
        $this->assertEquals($signature, $token->signature());
    }

    #[Test()]
    public function parse_must_return_a_non_signed_token_when_signature_algorithm_is_none(): void
    {
        $this->decoder->expects($this->exactly(3))
            ->method('base64UrlDecode')
            ->willReturnMap([
                ['a', 'a_dec'],
                ['b', 'b_dec'],
                ['c', 'c_dec'],
            ]);

        $this->decoder->expects($this->exactly(2))
            ->method('jsonDecode')
            ->willReturnMap([
                ['a_dec', ['typ' => 'JWT', 'alg' => 'none']],
                ['b_dec', [RegisteredClaims::AUDIENCE => 'test']],
            ]);

        $parser = $this->createParser();
        $token = $parser->parse('a.b.c');

        $this->assertInstanceOf(Plain::class, $token);

        $headers = new Headers(['typ' => 'JWT', 'alg' => 'none'], 'a');
        $claims = new Claims([RegisteredClaims::AUDIENCE => ['test']], 'b');
        $signature = new Signature('c_dec', 'c');

        $this->assertEquals($headers, $token->headers());
        $this->assertEquals($claims, $token->claims());
        $this->assertEquals($signature, $token->signature());
    }

    #[Test()]
    public function parse_must_return_a_signed_token_when_signature_is_informed(): void
    {
        $this->decoder->expects($this->exactly(3))
            ->method('base64UrlDecode')
            ->willReturnMap([
                ['a', 'a_dec'],
                ['b', 'b_dec'],
                ['c', 'c_dec'],
            ]);

        $this->decoder->expects($this->exactly(2))
            ->method('jsonDecode')
            ->willReturnMap([
                ['a_dec', ['typ' => 'JWT', 'alg' => 'HS256']],
                ['b_dec', [RegisteredClaims::AUDIENCE => 'test']],
            ]);

        $parser = $this->createParser();
        $token = $parser->parse('a.b.c');

        $this->assertInstanceOf(Plain::class, $token);

        $headers = new Headers(['typ' => 'JWT', 'alg' => 'HS256'], 'a');
        $claims = new Claims([RegisteredClaims::AUDIENCE => ['test']], 'b');
        $signature = new Signature('c_dec', 'c');

        $this->assertEquals($headers, $token->headers());
        $this->assertEquals($claims, $token->claims());
        $this->assertEquals($signature, $token->signature());
    }

    #[Test()]
    public function parse_must_convert_date_claims_to_objects(): void
    {
        $data = [
            RegisteredClaims::ISSUED_AT => 1_486_930_663,
            RegisteredClaims::EXPIRATION_TIME => 1_486_930_757.023_055,
        ];

        $this->decoder->expects($this->exactly(3))
            ->method('base64UrlDecode')
            ->willReturnMap([
                ['a', 'a_dec'],
                ['b', 'b_dec'],
                ['c', 'c_dec'],
            ]);

        $this->decoder->expects($this->exactly(2))
            ->method('jsonDecode')
            ->willReturnMap([
                ['a_dec', ['typ' => 'JWT', 'alg' => 'HS256']],
                ['b_dec', $data],
            ]);

        $token = $this->createParser()->parse('a.b.c');
        $this->assertInstanceOf(Plain::class, $token);

        $claims = $token->claims();

        $this->assertEquals(CarbonImmutable::createFromFormat('U', '1486930663'), $claims->get(RegisteredClaims::ISSUED_AT));

        $this->assertEquals(CarbonImmutable::createFromFormat('U.u', '1486930757.023055'), $claims->get(RegisteredClaims::EXPIRATION_TIME));
    }

    #[Test()]
    public function parse_must_convert_string_dates(): void
    {
        $data = [RegisteredClaims::NOT_BEFORE => '1486930757.000000'];

        $this->decoder->expects($this->exactly(3))
            ->method('base64UrlDecode')
            ->willReturnMap([
                ['a', 'a_dec'],
                ['b', 'b_dec'],
                ['c', 'c_dec'],
            ]);

        $this->decoder->expects($this->exactly(2))
            ->method('jsonDecode')
            ->willReturnMap([
                ['a_dec', ['typ' => 'JWT', 'alg' => 'HS256']],
                ['b_dec', $data],
            ]);

        $token = $this->createParser()->parse('a.b.c');
        $this->assertInstanceOf(Plain::class, $token);

        $claims = $token->claims();

        $this->assertEquals(CarbonImmutable::createFromFormat('U.u', '1486930757.000000'), $claims->get(RegisteredClaims::NOT_BEFORE));
    }

    #[Test()]
    public function parse_should_raise_exception_on_invalid_date(): void
    {
        $data = [RegisteredClaims::ISSUED_AT => '14/10/2018 10:50:10.10 UTC'];

        $this->decoder->expects($this->exactly(2))
            ->method('base64UrlDecode')
            ->willReturnMap([
                ['a', 'a_dec'],
                ['b', 'b_dec'],
            ]);

        $this->decoder->expects($this->exactly(2))
            ->method('jsonDecode')
            ->willReturnMap([
                ['a_dec', ['typ' => 'JWT', 'alg' => 'HS256']],
                ['b_dec', $data],
            ]);

        $this->expectException(InvalidTokenStructure::class);
        $this->expectExceptionMessage('Value is not in the allowed date format: 14/10/2018 10:50:10.10 UTC');
        $this->createParser()->parse('a.b.c');
    }

    #[Test()]
    public function parse_should_raise_exception_on_timestamp_beyond_date_time_immutable_range(): void
    {
        $data = [RegisteredClaims::ISSUED_AT => -10_000_000_000 ** 5];

        $this->decoder->expects($this->exactly(2))
            ->method('base64UrlDecode')
            ->willReturnMap([
                ['a', 'a_dec'],
                ['b', 'b_dec'],
            ]);

        $this->decoder->expects($this->exactly(2))
            ->method('jsonDecode')
            ->willReturnMap([
                ['a_dec', ['typ' => 'JWT', 'alg' => 'HS256']],
                ['b_dec', $data],
            ]);

        $this->expectException(InvalidTokenStructure::class);
        $this->createParser()->parse('a.b.c');
    }

    private function createParser(): Parser
    {
        return new Parser($this->decoder);
    }
}

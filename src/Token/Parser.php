<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Token;

use Carbon\CarbonImmutable;
use Carbon\Exceptions\InvalidFormatException;
use Cline\JWT\Contracts\DecoderInterface;
use Cline\JWT\Contracts\ParserInterface;
use Cline\JWT\Contracts\TokenInterface;
use Cline\JWT\Exceptions\MissingClaimsPart;
use Cline\JWT\Exceptions\MissingHeaderPart;
use Cline\JWT\Exceptions\MissingSignaturePart;
use Cline\JWT\Exceptions\MissingTokenSeparators;
use Cline\JWT\Exceptions\TokenPartMustBeArray;
use Cline\JWT\Exceptions\UnparseableDateClaimValue;
use Cline\JWT\Exceptions\UnsupportedHeaderFound;
use Cline\JWT\Token\RegisteredClaims;

use function array_key_exists;
use function array_keys;
use function count;
use function explode;
use function get_debug_type;
use function is_array;
use function is_float;
use function is_int;
use function is_numeric;
use function is_string;
use function number_format;

/**
 * Parser for compact signed JWT strings.
 *
 * The parser is responsible for structural validation, JOSE header normalization,
 * decoding of claims and signature segments, and coercion of registered date claims
 * into Carbon instances. It intentionally stops short of signature verification so
 * parsing and validation remain separate concerns.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class Parser implements ParserInterface
{
    private const int MICROSECOND_PRECISION = 6;

    /**
     * @param DecoderInterface $decoder Decoder used for Base64Url and JSON segments
     */
    public function __construct(
        private DecoderInterface $decoder,
    ) {}

    /**
     * Parse a compact JWT into the package's plain token representation.
     */
    public function parse(string $jwt): TokenInterface
    {
        [$encodedHeaders, $encodedClaims, $encodedSignature] = $this->splitJwt($jwt);

        if ($encodedHeaders === '') {
            throw MissingHeaderPart::detected();
        }

        if ($encodedClaims === '') {
            throw MissingClaimsPart::detected();
        }

        if ($encodedSignature === '') {
            throw MissingSignaturePart::detected();
        }

        $header = $this->parseHeader($encodedHeaders);

        return new Plain(
            new Headers($header, $encodedHeaders),
            new Claims($this->parseClaims($encodedClaims), $encodedClaims),
            $this->parseSignature($encodedSignature),
        );
    }

    /**
     * Split the compact JWT string into its three transport segments.
     *
     * @param non-empty-string $jwt
     *
     * @throws MissingTokenSeparators When JWT doesn't have all parts.
     * @return array<string>
     */
    private function splitJwt(string $jwt): array
    {
        $data = explode('.', $jwt);

        if (count($data) !== 3) {
            throw MissingTokenSeparators::detected();
        }

        return $data;
    }

    /**
     * Decode and normalize the JOSE header segment.
     *
     * @param non-empty-string $data
     *
     * @throws TokenPartMustBeArray           When parsed content isn't an array.
     * @throws UnsupportedHeaderFound         When an invalid header is informed.
     * @return array<non-empty-string, mixed>
     */
    private function parseHeader(string $data): array
    {
        $header = $this->decoder->jsonDecode($this->decoder->base64UrlDecode($data));

        if (!is_array($header)) {
            throw TokenPartMustBeArray::forPart('headers');
        }

        $this->guardAgainstEmptyStringKeys($header, 'headers');

        if (array_key_exists('enc', $header)) {
            throw UnsupportedHeaderFound::encryption();
        }

        if (!array_key_exists('typ', $header)) {
            $header['typ'] = 'JWT';
        }

        return $header;
    }

    /**
     * Decode the claims segment and normalize registered claim shapes.
     *
     * @param non-empty-string $data
     *
     * @throws TokenPartMustBeArray           When parsed content isn't an array.
     * @throws UnparseableDateClaimValue      When claims contain non-parseable dates.
     * @return array<non-empty-string, mixed>
     */
    private function parseClaims(string $data): array
    {
        $claims = $this->decoder->jsonDecode($this->decoder->base64UrlDecode($data));

        if (!is_array($claims)) {
            throw TokenPartMustBeArray::forPart('claims');
        }

        $this->guardAgainstEmptyStringKeys($claims, 'claims');

        if (array_key_exists(RegisteredClaims::AUDIENCE, $claims)) {
            $claims[RegisteredClaims::AUDIENCE] = (array) $claims[RegisteredClaims::AUDIENCE];
        }

        foreach (RegisteredClaims::DATE_CLAIMS as $claim) {
            if (!array_key_exists($claim, $claims)) {
                continue;
            }

            $claims[$claim] = $this->convertDate($claims[$claim]);
        }

        return $claims;
    }

    /**
     * Ensure the decoded structure uses only non-empty string keys.
     *
     * @param array<mixed, mixed> $array
     * @param non-empty-string    $part
     *
     * @phpstan-assert array<non-empty-string, mixed> $array
     */
    private function guardAgainstEmptyStringKeys(array $array, string $part): void
    {
        foreach (array_keys($array) as $key) {
            if ($key === '') {
                throw TokenPartMustBeArray::forPart($part);
            }
        }
    }

    /**
     * Convert a registered date claim into a CarbonImmutable instance.
     *
     * @throws UnparseableDateClaimValue
     */
    private function convertDate(mixed $timestamp): CarbonImmutable
    {
        if (!is_int($timestamp) && !is_float($timestamp) && !is_string($timestamp)) {
            throw UnparseableDateClaimValue::fromValue(get_debug_type($timestamp));
        }

        if (!is_numeric($timestamp)) {
            throw UnparseableDateClaimValue::fromValue($timestamp);
        }

        $normalizedTimestamp = number_format((float) $timestamp, self::MICROSECOND_PRECISION, '.', '');

        try {
            $date = CarbonImmutable::createFromFormat('U.u', $normalizedTimestamp);
        } catch (InvalidFormatException) {
            throw UnparseableDateClaimValue::fromValue($normalizedTimestamp);
        }

        if (!$date instanceof CarbonImmutable) {
            throw UnparseableDateClaimValue::fromValue($normalizedTimestamp);
        }

        return $date;
    }

    /**
     * Decode the signature segment and wrap it in the signature value object.
     *
     * @param non-empty-string $data
     */
    private function parseSignature(string $data): Signature
    {
        $hash = $this->decoder->base64UrlDecode($data);

        return new Signature($hash, $data);
    }
}

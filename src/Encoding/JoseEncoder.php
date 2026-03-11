<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Encoding;

use Cline\JWT\Contracts\DecoderInterface;
use Cline\JWT\Contracts\EncoderInterface;
use Cline\JWT\Encoding\Support\SodiumBase64Polyfill;
use Cline\JWT\Exceptions\CannotDecodeContent;
use Cline\JWT\Exceptions\CannotEncodeContent;
use Cline\JWT\Exceptions\InvalidJsonContent;
use JsonException;

use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use const JSON_UNESCAPED_UNICODE;

use function json_decode;
use function json_encode;

/**
 * Default JOSE encoder/decoder for JSON and Base64Url token segments.
 *
 * This class centralizes the wire-format rules used by both token issuance and
 * parsing. JSON operations always throw package exceptions with the underlying
 * JsonException attached, while Base64Url handling is delegated to the sodium
 * polyfill so environments with and without ext-sodium behave consistently.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class JoseEncoder implements DecoderInterface, EncoderInterface
{
    /**
     * Encode structured data as canonical JSON for JWT headers or claims.
     *
     * @throws CannotEncodeContent
     */
    public function jsonEncode(mixed $data): string
    {
        try {
            return json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        } catch (JsonException $jsonException) {
            throw CannotEncodeContent::jsonIssues($jsonException);
        }
    }

    /**
     * Decode a JSON token segment into associative PHP structures.
     *
     * @throws CannotDecodeContent
     */
    public function jsonDecode(string $json): mixed
    {
        try {
            return json_decode(json: $json, associative: true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $jsonException) {
            throw InvalidJsonContent::detected($jsonException);
        }
    }

    /**
     * Encode binary data using the JOSE Base64Url alphabet without padding.
     */
    public function base64UrlEncode(string $data): string
    {
        return SodiumBase64Polyfill::bin2base64(
            $data,
            SodiumBase64Polyfill::SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING,
        );
    }

    /**
     * Decode a JOSE Base64Url segment back to its binary representation.
     *
     * @throws CannotDecodeContent
     */
    public function base64UrlDecode(string $data): string
    {
        return SodiumBase64Polyfill::base642bin(
            $data,
            SodiumBase64Polyfill::SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING,
        );
    }
}

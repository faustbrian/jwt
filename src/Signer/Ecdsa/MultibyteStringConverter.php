<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Signer\Ecdsa;

use Cline\JWT\Contracts\Signer\Ecdsa\SignatureConverterInterface;
use Cline\JWT\Exceptions\ConversionFailed;
use Cline\JWT\Exceptions\InvalidAsn1Integer;
use Cline\JWT\Exceptions\InvalidAsn1StartSequence;
use Cline\JWT\Exceptions\InvalidSignatureLength;
use Illuminate\Support\Str;

use const STR_PAD_LEFT;

use function assert;
use function bin2hex;
use function dechex;
use function hex2bin;
use function hexdec;
use function is_string;
use function mb_str_pad;
use function mb_strlen;
use function mb_substr;

/**
 * ECDSA signature converter implemented with multibyte-safe string primitives.
 *
 * OpenSSL emits ECDSA signatures as ASN.1 DER sequences, while JWT/JWA requires
 * a fixed-width concatenation of the `R` and `S` coordinates. This converter is
 * the normalization layer between those formats. It also preserves positive ASN.1
 * integer semantics by adding or removing leading zero octets when the most
 * significant bit would otherwise make a coordinate look negative.
 *
 * The implementation uses `mb_*` functions because all intermediate values are
 * manipulated as hexadecimal strings rather than raw binary, and width handling
 * must stay byte-accurate across platforms.
 *
 * @author Brian Faust <brian@cline.sh>
 * @internal
 * @psalm-immutable
 */
final readonly class MultibyteStringConverter implements SignatureConverterInterface
{
    private const string ASN1_SEQUENCE = '30';

    private const string ASN1_INTEGER = '02';

    private const int ASN1_MAX_SINGLE_BYTE = 128;

    private const string ASN1_LENGTH_2BYTES = '81';

    private const string ASN1_BIG_INTEGER_LIMIT = '7f';

    private const string ASN1_NEGATIVE_INTEGER = '00';

    private const int BYTE_SIZE = 2;

    /**
     * Convert a JWA concatenated `R || S` signature into ASN.1 DER for OpenSSL.
     *
     * @throws ConversionFailed When the provided signature width does not match the
     *                          expected coordinate length.
     */
    public function toAsn1(string $points, int $length): string
    {
        $points = bin2hex($points);

        if ($this->octetLength($points) !== $length) {
            throw InvalidSignatureLength::detected();
        }

        $pointR = $this->preparePositiveInteger(mb_substr($points, 0, $length));
        $pointS = $this->preparePositiveInteger(mb_substr($points, $length));

        $lengthR = $this->octetLength($pointR);
        $lengthS = $this->octetLength($pointS);

        $totalLength = $lengthR + $lengthS + self::BYTE_SIZE + self::BYTE_SIZE;
        $lengthPrefix = $totalLength > self::ASN1_MAX_SINGLE_BYTE ? self::ASN1_LENGTH_2BYTES : '';

        $asn1 = hex2bin(
            self::ASN1_SEQUENCE
            .$lengthPrefix.dechex($totalLength)
            .self::ASN1_INTEGER.dechex($lengthR).$pointR
            .self::ASN1_INTEGER.dechex($lengthS).$pointS,
        );
        assert(is_string($asn1));
        assert($asn1 !== '');

        return $asn1;
    }

    /**
     * Convert an ASN.1 DER signature emitted by OpenSSL into JWA's fixed-width form.
     *
     * @throws ConversionFailed When the DER structure does not contain the expected
     *                          ASN.1 sequence or integer layout.
     */
    public function fromAsn1(string $signature, int $length): string
    {
        $message = bin2hex($signature);
        $position = 0;

        if ($this->readAsn1Content($message, $position, self::BYTE_SIZE) !== self::ASN1_SEQUENCE) {
            throw InvalidAsn1StartSequence::detected();
        }

        // @phpstan-ignore-next-line
        if ($this->readAsn1Content($message, $position, self::BYTE_SIZE) === self::ASN1_LENGTH_2BYTES) {
            $position += self::BYTE_SIZE;
        }

        $pointR = $this->retrievePositiveInteger($this->readAsn1Integer($message, $position));
        $pointS = $this->retrievePositiveInteger($this->readAsn1Integer($message, $position));

        $points = hex2bin(mb_str_pad($pointR, $length, '0', STR_PAD_LEFT).mb_str_pad($pointS, $length, '0', STR_PAD_LEFT));
        assert(is_string($points));
        assert($points !== '');

        return $points;
    }

    /**
     * Read a slice from the hexadecimal message while advancing the cursor.
     */
    private function readAsn1Content(string $message, int &$position, int $length): string
    {
        $content = mb_substr($message, $position, $length);
        $position += $length;

        return $content;
    }

    /**
     * Convert a hexadecimal string length into ASN.1 octet count.
     */
    private function octetLength(string $data): int
    {
        return (int) (mb_strlen($data) / self::BYTE_SIZE);
    }

    /**
     * Ensure a coordinate is encoded as a positive ASN.1 integer.
     *
     * Leading zeroes are trimmed when they are redundant and reintroduced when the
     * highest bit would otherwise indicate a negative integer.
     */
    private function preparePositiveInteger(string $data): string
    {
        if (mb_substr($data, 0, self::BYTE_SIZE) > self::ASN1_BIG_INTEGER_LIMIT) {
            return self::ASN1_NEGATIVE_INTEGER.$data;
        }

        while (
            Str::startsWith($data, self::ASN1_NEGATIVE_INTEGER)
            && mb_substr($data, 2, self::BYTE_SIZE) <= self::ASN1_BIG_INTEGER_LIMIT
        ) {
            $data = mb_substr($data, 2);
        }

        return $data;
    }

    /**
     * Read a single ASN.1 INTEGER payload from the current cursor position.
     *
     * @throws ConversionFailed When the next token is not an ASN.1 INTEGER.
     */
    private function readAsn1Integer(string $message, int &$position): string
    {
        if ($this->readAsn1Content($message, $position, self::BYTE_SIZE) !== self::ASN1_INTEGER) {
            throw InvalidAsn1Integer::detected();
        }

        $length = (int) hexdec($this->readAsn1Content($message, $position, self::BYTE_SIZE));

        return $this->readAsn1Content($message, $position, $length * self::BYTE_SIZE);
    }

    /**
     * Remove only the sign-preserving zero prefix added for ASN.1 positivity.
     */
    private function retrievePositiveInteger(string $data): string
    {
        while (
            Str::startsWith($data, self::ASN1_NEGATIVE_INTEGER)
            && mb_substr($data, 2, self::BYTE_SIZE) > self::ASN1_BIG_INTEGER_LIMIT
        ) {
            $data = mb_substr($data, 2);
        }

        return $data;
    }
}

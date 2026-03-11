<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Contracts\Signer\Ecdsa;

use Cline\JWT\Exceptions\ConversionFailed;

/**
 * Converts ECDSA signatures between OpenSSL's ASN.1 format and JWA's raw format.
 *
 * JWTs require ECDSA signatures to be emitted as the concatenated R and S points
 * in fixed-width big-endian octet strings, while OpenSSL signs and verifies using
 * ASN.1 DER structures. This contract isolates that impedance mismatch so the
 * signer can stay focused on algorithm selection and key validation.
 *
 * @author Brian Faust <brian@cline.sh>
 * @internal
 * @see https://tools.ietf.org/html/rfc7518#page-9
 * @see https://en.wikipedia.org/wiki/Abstract_Syntax_Notation_One
 */
interface SignatureConverterInterface
{
    /**
     * Convert an ASN.1 DER signature returned by OpenSSL into JWT wire format.
     *
     * Implementations must validate the encoded structure and left-pad or trim
     * the R and S integers so the returned string always matches the expected
     * curve point width.
     *
     * @throws ConversionFailed When there was an issue during the format conversion.
     *
     * @return non-empty-string
     */
    public function fromAsn1(string $signature, int $length): string;

    /**
     * Convert a JWT raw-point signature back into ASN.1 DER for OpenSSL.
     *
     * The `$points` payload must contain the concatenated R and S values with the
     * exact width expected for the configured curve.
     *
     * @param non-empty-string $points
     *
     * @throws ConversionFailed When there was an issue during the format conversion.
     *
     * @return non-empty-string
     */
    public function toAsn1(string $points, int $length): string;
}

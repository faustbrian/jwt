<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Contracts;

use Cline\JWT\Exceptions\CannotDecodeContent;
use NoDiscard;

/**
 * Decodes JWT string segments back into PHP values.
 *
 * Decoders mirror {@see EncoderInterface} and provide the inverse operations
 * needed by parsers and key loaders. Implementations are expected to enforce
 * the same serialization rules used during encoding so malformed or tampered
 * payloads fail deterministically instead of leaking inconsistent values into
 * later validation stages.
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface DecoderInterface
{
    /**
     * Decode a JWT JSON segment into its PHP representation.
     *
     * Implementations must raise an exception when the JSON cannot be decoded
     * cleanly, rather than returning partially decoded data or suppressing
     * parser errors.
     *
     * @param non-empty-string $json
     *
     * @throws CannotDecodeContent When something goes wrong while decoding.
     */
    #[NoDiscard()]
    public function jsonDecode(string $json): mixed;

    /**
     * Decode a base64url segment from compact JWT transport form.
     *
     * This method is used for compact token parsing as well as key material
     * helpers that accept URL-safe encoded input.
     *
     * @see http://tools.ietf.org/html/rfc4648#section-5
     *
     * @throws CannotDecodeContent                                     When something goes wrong while decoding.
     * @return ($data is non-empty-string ? non-empty-string : string)
     */
    #[NoDiscard()]
    public function base64UrlDecode(string $data): string;
}

<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Contracts\Signer;

/**
 * Read-only container for signer key material.
 *
 * Key objects decouple the rest of the JWT pipeline from where secret or
 * asymmetric key bytes originate. Implementations are expected to preserve the
 * raw key contents exactly as loaded and optionally expose a passphrase for
 * backends, such as OpenSSL, that need it when opening encrypted private keys.
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface KeyInterface
{
    /**
     * Return the raw key contents consumed by the signer backend.
     *
     * @return non-empty-string
     */
    public function contents(): string;

    /**
     * Return the passphrase associated with the key contents.
     *
     * Signers that do not need a passphrase may ignore this value, but the
     * contract keeps it available so encrypted private keys can be represented
     * without leaking backend-specific concerns into callers.
     */
    public function passphrase(): string;
}

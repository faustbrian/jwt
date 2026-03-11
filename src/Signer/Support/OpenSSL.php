<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Signer\Support;

use Cline\JWT\Contracts\Signer\KeyInterface;
use Cline\JWT\Contracts\SignerInterface;
use Cline\JWT\Exceptions\CannotSignPayload;
use Cline\JWT\Exceptions\InvalidKeyProvided;
use Cline\JWT\Exceptions\UnparseableKeyProvided;
use OpenSSLAsymmetricKey;

use const OPENSSL_KEYTYPE_DH;
use const OPENSSL_KEYTYPE_DSA;
use const OPENSSL_KEYTYPE_EC;
use const OPENSSL_KEYTYPE_RSA;
use const PHP_EOL;

use function array_key_exists;
use function assert;
use function is_array;
use function is_bool;
use function is_int;
use function is_string;
use function openssl_error_string;
use function openssl_pkey_get_details;
use function openssl_pkey_get_private;
use function openssl_pkey_get_public;
use function openssl_sign;
use function openssl_verify;

/**
 * Shared OpenSSL-backed implementation for asymmetric JWT signers.
 *
 * RSA and ECDSA variants both need the same sequence: load key material from
 * the package key abstraction, validate that OpenSSL parsed the expected key
 * type and size, then call the OpenSSL signing or verification primitive with
 * the algorithm constant chosen by the concrete signer.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
abstract readonly class OpenSSL implements SignerInterface
{
    protected const array KEY_TYPE_MAP = [
        OPENSSL_KEYTYPE_RSA => 'RSA',
        OPENSSL_KEYTYPE_DSA => 'DSA',
        OPENSSL_KEYTYPE_DH => 'DH',
        OPENSSL_KEYTYPE_EC => 'EC',
    ];

    /**
     * Return the OpenSSL algorithm constant used for signing and verification.
     */
    abstract public function algorithm(): int;

    /**
     * Create a raw binary signature for the payload with the provided private key.
     *
     * The key is resolved through OpenSSL so encrypted private keys can use the
     * passphrase exposed by the key object.
     *
     * @throws CannotSignPayload
     * @throws InvalidKeyProvided
     *
     * @return non-empty-string
     */
    final protected function createSignature(
        KeyInterface $key,
        string $payload,
    ): string {
        $opensslKey = $this->getPrivateKey($key);

        $signature = '';

        if (!openssl_sign($payload, $signature, $opensslKey, $this->algorithm())) {
            throw CannotSignPayload::errorHappened($this->fullOpenSSLErrorString());
        }

        assert(is_string($signature) && $signature !== '');

        return $signature;
    }

    /**
     * Verify a raw signature with the provided public key.
     *
     * @throws InvalidKeyProvided
     */
    final protected function verifySignature(
        string $expected,
        string $payload,
        KeyInterface $key,
    ): bool {
        $opensslKey = $this->getPublicKey($key);
        $result = openssl_verify($payload, $expected, $opensslKey, $this->algorithm());

        return $result === 1;
    }

    /**
     * Reject parsed OpenSSL keys that do not match the signer's algorithm requirements.
     *
     * @throws InvalidKeyProvided
     */
    abstract protected function guardAgainstIncompatibleKey(int $type, int $lengthInBits): void;

    /**
     * Resolve and validate a private key resource from package key material.
     *
     * @throws CannotSignPayload
     */
    private function getPrivateKey(
        KeyInterface $key,
    ): OpenSSLAsymmetricKey {
        return $this->validateKey(openssl_pkey_get_private($key->contents(), $key->passphrase()));
    }

    /**
     * Resolve and validate a public key resource from package key material.
     *
     * @throws InvalidKeyProvided
     */
    private function getPublicKey(KeyInterface $key): OpenSSLAsymmetricKey
    {
        return $this->validateKey(openssl_pkey_get_public($key->contents()));
    }

    /**
     * Validate that OpenSSL parsed the key and exposed usable metadata.
     *
     * Parsed keys are passed to the concrete signer for algorithm-specific type
     * and length checks before the OpenSSL handle is returned to the caller.
     *
     * @throws InvalidKeyProvided
     */
    private function validateKey(OpenSSLAsymmetricKey|bool $key): OpenSSLAsymmetricKey
    {
        if (is_bool($key)) {
            throw UnparseableKeyProvided::because($this->fullOpenSSLErrorString());
        }

        $details = openssl_pkey_get_details($key);
        assert(is_array($details));

        assert(array_key_exists('bits', $details));
        assert(is_int($details['bits']));
        assert(array_key_exists('type', $details));
        assert(is_int($details['type']));

        $this->guardAgainstIncompatibleKey($details['type'], $details['bits']);

        return $key;
    }

    /**
     * Drain the OpenSSL error queue into a multiline diagnostic string.
     */
    private function fullOpenSSLErrorString(): string
    {
        $error = '';

        while ($msg = openssl_error_string()) {
            $error .= PHP_EOL.'* '.$msg;
        }

        return $error;
    }
}

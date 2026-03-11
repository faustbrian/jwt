<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Support;

use Cline\JWT\Contracts\JwtProfileRepositoryInterface;
use Cline\JWT\Contracts\Signer\KeyInterface;
use Cline\JWT\Contracts\SignerInterface;
use Cline\JWT\Exceptions\InvalidProfileConfiguration;
use Cline\JWT\Exceptions\JwtProfileNotFound;
use Cline\JWT\JwtProfile;
use Cline\JWT\Signer\Key\InMemory;
use DateInterval;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;

use function array_is_list;
use function array_map;
use function assert;
use function is_array;
use function is_string;

/**
 * Resolves named JWT profiles from Laravel configuration arrays.
 *
 * This repository is the bridge between human-maintained config and the strongly
 * typed JwtProfile model. It validates every profile field aggressively so invalid
 * signer classes, malformed key loaders, or badly shaped headers and claims fail at
 * resolution time with profile-specific diagnostics.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class ConfigJwtProfileRepository implements JwtProfileRepositoryInterface
{
    /**
     * @param Container  $container Laravel container used to resolve signer classes
     * @param Repository $config    Configuration repository containing `jwt.*`
     */
    public function __construct(
        private Container $container,
        private Repository $config,
    ) {}

    /**
     * Resolve the configured default profile.
     */
    public function default(): JwtProfile
    {
        $name = $this->config->get('jwt.default', 'default');
        assert(is_string($name));

        return $this->get($name);
    }

    /**
     * Resolve a named profile from configuration and convert it into a JwtProfile.
     *
     * Passing null reuses the configured default profile name.
     */
    public function get(?string $name = null): JwtProfile
    {
        $name ??= $this->default()->name();
        $profile = $this->config->get('jwt.profiles.'.$name);

        if (!is_array($profile)) {
            throw JwtProfileNotFound::named($name);
        }

        return new JwtProfile(
            $name,
            $this->resolveSigner($name, $profile['signer'] ?? null),
            $this->resolveKey($name, 'signing_key', $profile['signing_key'] ?? null),
            $this->resolveKey($name, 'verification_key', $profile['verification_key'] ?? null),
            $this->resolveDateInterval($name, 'ttl', $profile['ttl'] ?? null),
            $this->resolveDateInterval($name, 'leeway', $profile['leeway'] ?? null),
            $this->resolveNullableString($name, 'issuer', $profile['issuer'] ?? null),
            $this->resolveStringList($name, 'audiences', $profile['audiences'] ?? []),
            $this->resolveAssociativeArray($name, 'headers', $profile['headers'] ?? []),
            $this->resolveAssociativeArray($name, 'claims', $profile['claims'] ?? []),
        );
    }

    /**
     * Resolve a signer from either a prebuilt instance or a container class name.
     */
    private function resolveSigner(string $profile, mixed $signer): SignerInterface
    {
        if ($signer instanceof SignerInterface) {
            return $signer;
        }

        if (is_string($signer) && $signer !== '') {
            $resolved = $this->container->make($signer);
            assert($resolved instanceof SignerInterface);

            return $resolved;
        }

        throw InvalidProfileConfiguration::forProfile($profile, 'a valid signer must be configured');
    }

    /**
     * Resolve a key definition using one of the supported loaders.
     *
     * Key arrays may specify `source`, `contents`, or `path` depending on the loader.
     */
    private function resolveKey(string $profile, string $field, mixed $value): KeyInterface
    {
        if ($value instanceof KeyInterface) {
            return $value;
        }

        if (!is_array($value)) {
            throw InvalidProfileConfiguration::forProfile($profile, $field.' must be a key definition array');
        }

        $loader = $value['loader'] ?? 'plain';
        $passphrase = $value['passphrase'] ?? '';

        if (!is_string($loader) || !is_string($passphrase)) {
            throw InvalidProfileConfiguration::forProfile($profile, $field.' loader configuration is invalid');
        }

        $source = $value['source'] ?? $value['contents'] ?? $value['path'] ?? null;

        if (!is_string($source) || $source === '') {
            throw InvalidProfileConfiguration::forProfile($profile, $field.' source must be a non-empty string');
        }

        return match ($loader) {
            'plain' => InMemory::plainText($source, $passphrase),
            'base64' => InMemory::base64Encoded($source, $passphrase),
            'file' => InMemory::file($source, $passphrase),
            default => throw InvalidProfileConfiguration::forProfile(
                $profile,
                $field.' loader must be one of [plain, base64, file]',
            ),
        };
    }

    /**
     * Resolve an optional ISO-8601 interval field into a DateInterval instance.
     */
    private function resolveDateInterval(string $profile, string $field, mixed $value): ?DateInterval
    {
        if ($value === null) {
            return null;
        }

        if ($value instanceof DateInterval) {
            return $value;
        }

        if (!is_string($value) || $value === '') {
            throw InvalidProfileConfiguration::forProfile($profile, $field.' must be an ISO-8601 interval string');
        }

        return new DateInterval($value);
    }

    /**
     * Resolve an optional scalar string field while preserving null as "unset".
     */
    private function resolveNullableString(string $profile, string $field, mixed $value): ?string
    {
        if ($value === null) {
            return null;
        }

        if (!is_string($value)) {
            throw InvalidProfileConfiguration::forProfile($profile, $field.' must be a string or null');
        }

        return $value;
    }

    /**
     * Resolve a list field and ensure it contains only non-empty strings.
     *
     * @return array<non-empty-string>
     */
    private function resolveStringList(string $profile, string $field, mixed $value): array
    {
        if (!is_array($value) || !array_is_list($value)) {
            throw InvalidProfileConfiguration::forProfile($profile, $field.' must be a list of strings');
        }

        $values = array_map(
            static function (mixed $item) use ($profile, $field): string {
                if (!is_string($item) || $item === '') {
                    throw InvalidProfileConfiguration::forProfile($profile, $field.' must contain only non-empty strings');
                }

                return $item;
            },
            $value,
        );

        return [...$values];
    }

    /**
     * Resolve an associative map field with non-empty string keys.
     *
     * @return array<non-empty-string, mixed>
     */
    private function resolveAssociativeArray(string $profile, string $field, mixed $value): array
    {
        if (!is_array($value) || ($value !== [] && array_is_list($value))) {
            throw InvalidProfileConfiguration::forProfile($profile, $field.' must be an associative array');
        }

        $resolved = [];

        foreach ($value as $key => $item) {
            if (!is_string($key) || $key === '') {
                throw InvalidProfileConfiguration::forProfile($profile, $field.' keys must be non-empty strings');
            }

            $resolved[$key] = $item;
        }

        return $resolved;
    }
}

<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Benchmark;

use Bench\Groups;
use Bench\Iterations;
use Bench\ParamProviders;
use Bench\Revs;
use Bench\Subject;
use Bench\Warmup;
use Cline\JWT\Contracts\Signer\KeyInterface;
use Cline\JWT\Contracts\SignerInterface;
use Cline\JWT\Signer\Blake2bSigner;
use Cline\JWT\Signer\Ecdsa\Sha256 as EcdsaSha256;
use Cline\JWT\Signer\Ecdsa\Sha384 as EcdsaSha384;
use Cline\JWT\Signer\Ecdsa\Sha512 as EcdsaSha512;
use Cline\JWT\Signer\EdDsaSigner;
use Cline\JWT\Signer\Hmac\Sha256;
use Cline\JWT\Signer\Hmac\Sha384;
use Cline\JWT\Signer\Hmac\Sha512;
use Cline\JWT\Signer\Key\InMemory;
use Cline\JWT\Signer\Rsa\Sha256 as RsaSha256;
use Cline\JWT\Signer\Rsa\Sha384 as RsaSha384;
use Cline\JWT\Signer\Rsa\Sha512 as RsaSha512;
use Tests\Exceptions\UnknownBenchmarkAlgorithm;

/**
 * @author Brian Faust <brian@cline.sh>
 */
#[Iterations(5)]
#[Revs(100)]
#[Warmup(3)]
abstract class AlgorithmsBench
{
    protected const string PAYLOAD = "It\xe2\x80\x99s a dangerous business, Frodo, going out your door. You step"
        ." onto the road, and if you don't keep your feet, there\xe2\x80\x99s no knowing where you might be swept"
        .' off to.';

    private const array SUPPORTED_ALGORITHMS = [
        'hmac' => ['HS256', 'HS384', 'HS512'],
        'rsa' => ['RS256', 'RS384', 'RS512'],
        'ecdsa' => ['ES256', 'ES384', 'ES512'],
        'eddsa' => ['EdDSA'],
        'blake2b' => ['BLAKE2B'],
    ];

    #[Subject()]
    #[ParamProviders('hmacAlgorithms')]
    #[Groups(['hmac', 'symmetric'])]
    public function hmac(): void
    {
        $this->runBenchmark();
    }

    /**
     * @return iterable<string, array{algorithm: string}>
     */
    public function hmacAlgorithms(): iterable
    {
        yield from $this->iterateAlgorithms('hmac');
    }

    #[Subject()]
    #[ParamProviders('rsaAlgorithms')]
    #[Groups(['rsa', 'asymmetric'])]
    public function rsa(): void
    {
        $this->runBenchmark();
    }

    /**
     * @return iterable<string, array{algorithm: string}>
     */
    public function rsaAlgorithms(): iterable
    {
        yield from $this->iterateAlgorithms('rsa');
    }

    #[Subject()]
    #[ParamProviders('ecdsaAlgorithms')]
    #[Groups(['ecdsa', 'asymmetric'])]
    public function ecdsa(): void
    {
        $this->runBenchmark();
    }

    /**
     * @return iterable<string, array{algorithm: string}>
     */
    public function ecdsaAlgorithms(): iterable
    {
        yield from $this->iterateAlgorithms('ecdsa');
    }

    #[Subject()]
    #[ParamProviders('eddsaAlgorithms')]
    #[Groups(['eddsa', 'asymmetric'])]
    public function eddsa(): void
    {
        $this->runBenchmark();
    }

    /**
     * @return iterable<string, array{algorithm: string}>
     */
    public function eddsaAlgorithms(): iterable
    {
        yield from $this->iterateAlgorithms('eddsa');
    }

    #[Subject()]
    #[ParamProviders('blake2bAlgorithms')]
    #[Groups(['blake2b', 'symmetric'])]
    public function blake2b(): void
    {
        $this->runBenchmark();
    }

    /**
     * @return iterable<string, array{algorithm: string}>
     */
    public function blake2bAlgorithms(): iterable
    {
        yield from $this->iterateAlgorithms('blake2b');
    }

    protected function resolveAlgorithm(string $name): SignerInterface
    {
        return match ($name) {
            'HS256' => new Sha256(),
            'HS384' => new Sha384(),
            'HS512' => new Sha512(),
            'RS256' => new RsaSha256(),
            'RS384' => new RsaSha384(),
            'RS512' => new RsaSha512(),
            'ES256' => new EcdsaSha256(),
            'ES384' => new EcdsaSha384(),
            'ES512' => new EcdsaSha512(),
            'EdDSA' => new EdDsaSigner(),
            'BLAKE2B' => new Blake2bSigner(),
            default => throw UnknownBenchmarkAlgorithm::named($name),
        };
    }

    protected function resolveSigningKey(string $name): KeyInterface
    {
        return match ($name) {
            'HS256' => InMemory::base64Encoded('n5p7sBK+dvBmSKNlQIFrsuB1cnmnwsxGyWXPgRSZtWY='),
            'HS384' => InMemory::base64Encoded('kNUb8KvJC+fvhPzIuimwWHleES3AAnUjI+UIWZyor5HT33st9KIjfPkgtfu60UL2'),
            'HS512' => InMemory::base64Encoded(
                'OgXKIs+aZCQgXnDfi8mAFnWVo+Xn3JTR7BvT/j1Q1zP9oRx9xGg4jmpq00RsPPDclYi8+jRl664pu4d0zan2ow==',
            ),
            'RS256', 'RS384', 'RS512' => InMemory::file(__DIR__.'/Rsa/private.key'),
            'ES256' => InMemory::file(__DIR__.'/Ecdsa/private-256.key'),
            'ES384' => InMemory::file(__DIR__.'/Ecdsa/private-384.key'),
            'ES512' => InMemory::file(__DIR__.'/Ecdsa/private-521.key'),
            'EdDSA' => InMemory::base64Encoded(
                'K3NWT0XqaH+4jgi42gQmHnFE+HTPVhFYi3u4DFJ3OpRHRMt/aGRBoKD/Pt5H/iYgGCla7Q04CdjOUpLSrjZhtg==',
            ),
            'BLAKE2B' => InMemory::base64Encoded('b6DNRcX2SFapbICe6lXWYoOZA+JXL/dvkfWiv2hJv3Y='),
            default => throw UnknownBenchmarkAlgorithm::named($name),
        };
    }

    protected function resolveVerificationKey(string $name): KeyInterface
    {
        return match ($name) {
            'HS256', 'HS384', 'HS512', 'BLAKE2B' => $this->resolveSigningKey($name),
            'RS256', 'RS384', 'RS512' => InMemory::file(__DIR__.'/Rsa/public.key'),
            'ES256' => InMemory::file(__DIR__.'/Ecdsa/public-256.key'),
            'ES384' => InMemory::file(__DIR__.'/Ecdsa/public-384.key'),
            'ES512' => InMemory::file(__DIR__.'/Ecdsa/public-521.key'),
            'EdDSA' => InMemory::base64Encoded('R0TLf2hkQaCg/z7eR/4mIBgpWu0NOAnYzlKS0q42YbY='),
            default => throw UnknownBenchmarkAlgorithm::named($name),
        };
    }

    abstract protected function runBenchmark(): void;

    /**
     * @return iterable<string, array{algorithm: string}>
     */
    private function iterateAlgorithms(string $family): iterable
    {
        foreach (self::SUPPORTED_ALGORITHMS[$family] ?? [] as $algorithm) {
            yield $algorithm => ['algorithm' => $algorithm];
        }
    }
}

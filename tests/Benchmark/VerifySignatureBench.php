<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Benchmark;

use Bench\BeforeMethods;
use Cline\JWT\Contracts\Signer\KeyInterface;
use Cline\JWT\Contracts\SignerInterface;

/**
 * @author Brian Faust <brian@cline.sh>
 */
#[BeforeMethods('initialize')]
final class VerifySignatureBench extends AlgorithmsBench
{
    private SignerInterface $algorithm;

    private KeyInterface $key;

    /** @var non-empty-string */
    private string $signature;

    /**
     * @param array{algorithm: string} $params
     */
    public function initialize(array $params): void
    {
        $this->algorithm = $this->resolveAlgorithm($params['algorithm']);
        $this->key = $this->resolveVerificationKey($params['algorithm']);

        $this->signature = $this->algorithm->sign(
            self::PAYLOAD,
            $this->resolveSigningKey($params['algorithm']),
        );
    }

    protected function runBenchmark(): void
    {
        $this->algorithm->verify($this->signature, self::PAYLOAD, $this->key);
    }
}

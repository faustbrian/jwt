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
use Cline\JWT\IssueTokenRequest;
use Cline\JWT\JwtFacade;

/**
 * @author Brian Faust <brian@cline.sh>
 */
#[BeforeMethods('initialize')]
final class IssueTokenBench extends AlgorithmsBench
{
    private SignerInterface $algorithm;

    private KeyInterface $key;

    /**
     * @param array{algorithm: string} $params
     */
    public function initialize(array $params): void
    {
        $this->algorithm = $this->resolveAlgorithm($params['algorithm']);
        $this->key = $this->resolveSigningKey($params['algorithm']);
    }

    protected function runBenchmark(): void
    {
        new JwtFacade()->issue(
            $this->algorithm,
            $this->key,
            new IssueTokenRequest()
                ->identifiedBy('token-1')
                ->issuedBy('cline.jwt.benchmarks')
                ->relatedTo('user-1')
                ->permittedFor('cline.jwt'),
        );
    }
}

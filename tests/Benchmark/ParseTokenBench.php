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
use Cline\JWT\Validation\Constraint\IdentifiedBy;
use Cline\JWT\Validation\Constraint\IssuedBy;
use Cline\JWT\Validation\Constraint\PermittedFor;
use Cline\JWT\Validation\Constraint\RelatedTo;
use Cline\JWT\Validation\Constraint\SignedWith;
use Cline\JWT\Validation\Constraint\StrictValidAt;

/**
 * @author Brian Faust <brian@cline.sh>
 */
#[BeforeMethods('initialize')]
final class ParseTokenBench extends AlgorithmsBench
{
    private SignerInterface $algorithm;

    private KeyInterface $key;

    /** @var non-empty-string */
    private string $jwt;

    /**
     * @param array{algorithm: string} $params
     */
    public function initialize(array $params): void
    {
        $this->algorithm = $this->resolveAlgorithm($params['algorithm']);
        $this->key = $this->resolveVerificationKey($params['algorithm']);

        $this->jwt = new JwtFacade()->issue(
            $this->algorithm,
            $this->resolveSigningKey($params['algorithm']),
            new IssueTokenRequest()
                ->identifiedBy('token-1')
                ->issuedBy('cline.jwt.benchmarks')
                ->relatedTo('user-1')
                ->permittedFor('cline.jwt'),
        )->toString();
    }

    protected function runBenchmark(): void
    {
        new JwtFacade()->parse(
            $this->jwt,
            new SignedWith($this->algorithm, $this->key),
            new StrictValidAt(),
            new IssuedBy('cline.jwt.benchmarks'),
            new RelatedTo('user-1'),
            new PermittedFor('cline.jwt'),
            new IdentifiedBy('token-1'),
        );
    }
}

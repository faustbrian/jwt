<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

use function escapeshellarg;
use function exec;
use function realpath;

/**
 * @author Brian Faust <brian@cline.sh>
 * @internal
 */
final class RepositoryFixtureTest extends TestCase
{
    #[Test()]
    public function ecdsa_key_fixtures_are_not_ignored_by_git(): void
    {
        $fixture = 'tests/_keys/ecdsa/private.key';
        $command = $this->gitCheckIgnoreCommand($fixture);

        exec($command, $output, $exitCode);

        $this->assertSame(
            1,
            $exitCode,
            'ECDSA key fixtures must be trackable so CI receives them.',
        );
    }

    #[Test()]
    public function pem_key_fixtures_are_not_ignored_by_git(): void
    {
        $fixture = 'tests/Signer/Key/test.pem';
        $command = $this->gitCheckIgnoreCommand($fixture);

        exec($command, $output, $exitCode);

        $this->assertSame(
            1,
            $exitCode,
            'PEM fixtures must be trackable so CI receives them.',
        );
    }

    private function gitCheckIgnoreCommand(string $fixture): string
    {
        return 'git -c safe.directory='.escapeshellarg((string) realpath(__DIR__.'/..'))
            .' check-ignore '.escapeshellarg($fixture).' 2>/dev/null';
    }
}

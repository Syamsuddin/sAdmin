<?php

namespace Tests\Feature;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Finder\Finder;

/** ADR 0002 §2.2: hanya adaptor app/Infrastructure/WebAuthn yang boleh memakai pustaka WebAuthn/COSE/CBOR. */
class WebAuthnBoundaryTest extends TestCase
{
    public function test_only_the_adapter_uses_the_webauthn_library(): void
    {
        $app = dirname(__DIR__, 2).'/app';
        $offenders = [];
        foreach (Finder::create()->files()->in($app)->name('*.php') as $file) {
            if (str_starts_with($file->getPathname(), $app.'/Infrastructure/WebAuthn/')) {
                continue;
            }
            if (preg_match('/^\s*use\s+\\\\?(Webauthn|Cose|CBOR)\\\\/mi', (string) file_get_contents($file->getPathname())) === 1) {
                $offenders[] = $file->getRelativePathname();
            }
        }

        $this->assertSame([], $offenders, 'Pakai App\Infrastructure\WebAuthn\WebAuthnServer, bukan pustaka langsung.');
    }
}

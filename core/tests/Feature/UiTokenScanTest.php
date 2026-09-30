<?php

namespace Tests\Feature;

use Illuminate\Support\Facades\File;
use Tests\TestCase;

class UiTokenScanTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->dir = sys_get_temp_dir().'/sadmin-ui-'.bin2hex(random_bytes(4));
        File::makeDirectory($this->dir);
    }

    protected function tearDown(): void
    {
        File::deleteDirectory($this->dir);
        parent::tearDown();
    }

    public function test_console_ui_uses_only_tokens(): void
    {
        $this->artisan('sadmin:ui-token-scan')->assertExitCode(0);
    }

    public function test_reports_raw_colors_sizes_and_fonts(): void
    {
        File::put($this->dir.'/a.css', ".x { color: #1d4ed8; }\n.y { margin: 12px; }\n.z { background: rgba(0, 0, 0, .5); }\n.w { font-family: Arial; }\n");
        File::put($this->dir.'/b.blade.php', "<div style=\"padding: 1.5rem\">x</div>\n");

        $this->artisan('sadmin:ui-token-scan', ['paths' => [$this->dir]])
            ->expectsOutputToContain('a.css:1 — warna hex "#1d4ed8"')
            ->expectsOutputToContain('a.css:2 — ukuran berunit "12px"')
            ->expectsOutputToContain('a.css:3 — fungsi warna "rgba("')
            ->expectsOutputToContain('a.css:4 — font di luar token')
            ->expectsOutputToContain('b.blade.php:1 — ukuran berunit "1.5rem"')
            ->assertExitCode(1);
    }

    public function test_token_references_entities_and_ids_are_allowed(): void
    {
        File::put($this->dir.'/c.css', ".x { color: var(--color-primary); font-family: var(--font-ui); padding: var(--sp-4); }\n");
        File::put($this->dir.'/d.blade.php', "<a href=\"#main\">&#169; sAdmin</a> <input maxlength=\"60\">\n");

        $this->artisan('sadmin:ui-token-scan', ['paths' => [$this->dir]])->assertExitCode(0);
    }

    public function test_the_token_file_itself_is_the_one_place_for_raw_values(): void
    {
        $this->assertStringContainsString('#1D4ED8', (string) file_get_contents(resource_path('css/tokens.css')));
        $this->artisan('sadmin:ui-token-scan', ['paths' => [resource_path('css')]])->assertExitCode(0);
    }
}

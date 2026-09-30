<?php

namespace Tests\Feature;

use PHPUnit\Framework\TestCase;

/** docs/26: hanya Tabler Icons — setiap SVG di resources/icons/tabler identik dengan paket resmi. */
class TablerIconProvenanceTest extends TestCase
{
    public function test_every_vendored_icon_is_byte_identical_to_the_official_package(): void
    {
        $root = dirname(__DIR__, 2);
        $icons = glob($root.'/resources/icons/tabler/*.svg') ?: [];
        $this->assertNotEmpty($icons);

        foreach ($icons as $icon) {
            $official = $root.'/node_modules/@tabler/icons/icons/outline/'.basename($icon);
            $this->assertFileExists($official, basename($icon).' bukan ikon Tabler outline.');
            $this->assertSame(hash_file('sha256', $official), hash_file('sha256', $icon), basename($icon).' telah diubah.');
        }
        $this->assertFileExists($root.'/resources/icons/tabler/LICENSE');
    }
}

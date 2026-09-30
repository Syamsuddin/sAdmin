<?php

namespace Tests\Feature\Identity;

use App\Domain\Audit\Services\AuditChainVerifier;
use App\Domain\Identity\Actions\UpdateThemePreference;
use App\Domain\Identity\Data\ThemePreference;
use App\Http\Middleware\EnforceAbsoluteSessionLifetime;
use App\Models\Admin;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Testing\TestResponse;
use Symfony\Component\HttpFoundation\Response;
use Tests\Support\InteractsWithPasskeys;
use Tests\TestCase;

/** F-17, AC-01 docs/23: tema console light/dark per admin; `system` mengikuti OS (docs/26). */
class ThemePreferenceTest extends TestCase
{
    use InteractsWithPasskeys, RefreshDatabase;

    private const PAGE = '/pengaturan/passkey';

    private const FOLLOWS_OS = "matchMedia('(prefers-color-scheme: dark)')";

    private Admin $admin;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpInstitution();
        $this->admin = $this->newAdmin();
    }

    public function test_new_admin_follows_the_operating_system(): void
    {
        $page = $this->page($this->admin);

        $this->assertNull($this->renderedTheme($page));
        $page->assertSee(self::FOLLOWS_OS, false);
        $this->assertSame('system', $this->pressedOption($page));
    }

    public function test_dark_choice_survives_reload_with_server_rendered_attribute(): void
    {
        $this->choose($this->admin, 'dark')->assertRedirect(self::PAGE);

        $this->assertSame(ThemePreference::Dark, $this->admin->fresh()?->theme);
        $page = $this->page($this->admin);
        $this->assertSame('dark', $this->renderedTheme($page));
        $page->assertDontSee(self::FOLLOWS_OS, false);
        $this->assertSame('dark', $this->pressedOption($page));
    }

    public function test_light_choice_survives_reload_with_server_rendered_attribute(): void
    {
        $this->choose($this->admin, 'light')->assertRedirect(self::PAGE);

        $page = $this->page($this->admin);
        $this->assertSame('light', $this->renderedTheme($page));
        $page->assertDontSee(self::FOLLOWS_OS, false);
        $this->assertSame('light', $this->pressedOption($page));
    }

    public function test_choosing_system_again_hands_the_mode_back_to_the_os(): void
    {
        $this->choose($this->admin, 'dark');
        $this->choose($this->admin, 'system');

        $page = $this->page($this->admin);
        $this->assertNull($this->renderedTheme($page));
        $page->assertSee(self::FOLLOWS_OS, false);
        $this->assertSame('system', $this->pressedOption($page));
    }

    /** "Token gelap aktif": atribut di atas memilih blok ini; nilainya harus tabel dark docs/26. */
    public function test_dark_attribute_selects_the_dark_token_block(): void
    {
        $css = (string) file_get_contents(resource_path('css/tokens.css'));
        $this->assertSame(1, preg_match('/\[data-bs-theme="dark"\]\s*\{([^}]*)\}/', $css, $block));

        foreach (['--color-bg' => '#0F172A', '--color-surface' => '#1E293B', '--color-text' => '#F1F5F9', '--color-link' => '#60A5FA'] as $token => $value) {
            $this->assertStringContainsString("{$token}: {$value};", $block[1]);
        }
    }

    public function test_saving_confirms_with_a_success_toast(): void
    {
        $this->followingRedirects()->choose($this->admin, 'dark')
            ->assertOk()
            ->assertSee('role="status"', false)
            ->assertSee('Tema disimpan.');
    }

    public function test_theme_change_is_audited_with_previous_and_new_value(): void
    {
        $this->choose($this->admin, 'dark');
        $this->choose($this->admin, 'light');

        $entries = DB::table('audit_entries')->where('action_key', 'admin.theme_change')->orderBy('seq')->get();
        $this->assertCount(2, $entries);
        $this->assertSame('admin', $entries[0]->actor_type);
        $this->assertSame($this->admin->id, $entries[0]->actor_id);
        $this->assertSame('admin:'.$this->admin->id, $entries[0]->target);
        $this->assertSame('ok', $entries[0]->outcome);
        $this->assertSame(['from' => 'system', 'to' => 'dark'], $this->params($entries[0]->params_redacted));
        $this->assertSame(['from' => 'dark', 'to' => 'light'], $this->params($entries[1]->params_redacted));
        $this->assertTrue(app(AuditChainVerifier::class)->verify()->intact);
    }

    public function test_choosing_the_current_theme_is_not_a_state_change(): void
    {
        $this->choose($this->admin, 'system')->assertRedirect(self::PAGE);

        $this->assertSame(0, DB::table('audit_entries')->where('action_key', 'admin.theme_change')->count());
    }

    /** Dua tab: salinan admin di memori basi, audit tetap mencatat nilai yang tersimpan. */
    public function test_audit_records_the_stored_value_not_a_stale_copy(): void
    {
        $staleCopy = Admin::query()->findOrFail($this->admin->id);
        app(UpdateThemePreference::class)->handle($this->admin, ThemePreference::Dark);

        app(UpdateThemePreference::class)->handle($staleCopy, ThemePreference::Light);

        $last = DB::table('audit_entries')->where('action_key', 'admin.theme_change')->orderByDesc('seq')->first();
        $this->assertSame(['from' => 'dark', 'to' => 'light'], $this->params($last?->params_redacted));
        $this->assertSame(ThemePreference::Light, $staleCopy->theme);
    }

    public function test_unknown_theme_is_rejected_without_change_or_audit(): void
    {
        foreach (['sepia', '', 'DARK'] as $value) {
            $this->choose($this->admin, $value)->assertRedirect(self::PAGE)->assertSessionHasErrors('theme');
        }
        $this->choose($this->admin, null)->assertSessionHasErrors('theme');

        $this->assertSame(ThemePreference::System, $this->admin->fresh()?->theme);
        $this->assertSame(0, DB::table('audit_entries')->where('action_key', 'admin.theme_change')->count());
    }

    public function test_rejection_explains_step_cause_and_action(): void
    {
        $this->followingRedirects()->choose($this->admin, 'sepia')
            ->assertOk()
            ->assertSee('role="alert"', false)
            ->assertSee('Langkah Simpan tema gagal: pilihan tema tidak dikenal. Tindakan: pilih Ikuti sistem, Terang, atau Gelap.');
    }

    public function test_preference_belongs_to_one_admin_only(): void
    {
        $other = $this->newAdmin();

        $this->choose($this->admin, 'dark');

        $this->assertSame(ThemePreference::System, $other->fresh()?->theme);
        $this->assertNull($this->renderedTheme($this->page($other)));
    }

    public function test_guest_cannot_change_a_theme(): void
    {
        $this->put('/pengaturan/tema', ['theme' => 'dark'])->assertRedirect('/masuk');

        $this->assertSame(0, DB::table('admins')->where('theme', '!=', 'system')->count());
    }

    public function test_login_page_follows_the_operating_system(): void
    {
        $page = $this->get('/masuk')->assertOk();

        $this->assertNull($this->renderedTheme($page));
        $page->assertSee(self::FOLLOWS_OS, false);
    }

    /** @return TestResponse<Response> */
    private function page(Admin $admin): TestResponse
    {
        return $this->actingAs($admin)
            ->withSession([EnforceAbsoluteSessionLifetime::STARTED_AT => time()])
            ->get(self::PAGE)
            ->assertOk();
    }

    /**
     * Dikirim dari halaman console seperti formulir pengalih tema di topbar.
     *
     * @return TestResponse<Response>
     */
    private function choose(Admin $admin, ?string $theme): TestResponse
    {
        return $this->actingAs($admin)
            ->withSession([EnforceAbsoluteSessionLifetime::STARTED_AT => time()])
            ->from(self::PAGE)
            ->put('/pengaturan/tema', $theme === null ? [] : ['theme' => $theme]);
    }

    /**
     * Nilai `data-bs-theme` yang dirender server pada `<html>`; null = diserahkan ke skrip OS.
     *
     * @param  TestResponse<Response>  $page
     */
    private function renderedTheme(TestResponse $page): ?string
    {
        $this->assertSame(1, preg_match('/<html\b[^>]*>/', (string) $page->getContent(), $html));

        return preg_match('/\sdata-bs-theme="([^"]*)"/', $html[0], $theme) === 1 ? $theme[1] : null;
    }

    /**
     * jsonb menyimpan kunci terurut panjang; urutkan agar perbandingan tetap ketat tanpa bergantung urutan.
     *
     * @return array<string, mixed>
     */
    private function params(?string $json): array
    {
        $params = json_decode((string) $json, true);
        $this->assertIsArray($params);
        ksort($params);

        return $params;
    }

    /** @param  TestResponse<Response>  $page */
    private function pressedOption(TestResponse $page): string
    {
        preg_match_all('/<button\b[^>]*\bname="theme"[^>]*>/', (string) $page->getContent(), $buttons);
        $this->assertCount(3, $buttons[0]);
        $pressed = array_values(array_filter($buttons[0], fn (string $button): bool => str_contains($button, 'aria-pressed="true"')));
        $this->assertCount(1, $pressed);
        $this->assertSame(1, preg_match('/\bvalue="([^"]*)"/', $pressed[0], $value));

        return $value[1];
    }
}

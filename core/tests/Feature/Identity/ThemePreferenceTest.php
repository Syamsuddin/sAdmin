<?php

namespace Tests\Feature\Identity;

use App\Domain\Audit\Actions\AppendAuditEntry;
use App\Domain\Audit\Services\AuditChainVerifier;
use App\Domain\Identity\Actions\UpdateThemePreference;
use App\Domain\Identity\Data\ThemePreference;
use App\Http\Middleware\EnforceAbsoluteSessionLifetime;
use App\Models\Admin;
use Illuminate\Database\QueryException;
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
        $this->assertFollowsOs($page);
        $this->assertSame('system', $this->pressedOption($page));
        $this->assertSame(ThemePreference::System, (new Admin)->theme);
    }

    /** Tanpa token CSRF setiap klik berakhir 419 di produksi; tes Laravel mematikan pemeriksaannya, jadi markup dijaga di sini. */
    public function test_switch_is_a_csrf_protected_labelled_form(): void
    {
        $html = (string) $this->page($this->admin)->getContent();

        $this->assertSame(1, preg_match('#<form method="POST" action="[^"]*/pengaturan/tema">(.*?)</form>#s', $html, $form));
        $this->assertMatchesRegularExpression('/<input type="hidden" name="_token" value="[^"]+"/', $form[1]);
        $this->assertStringContainsString('<input type="hidden" name="_method" value="PUT">', $form[1]);
        $this->assertStringContainsString('role="group" aria-label="Mode tema"', $form[1]);
        foreach (['Ikuti sistem', 'Terang', 'Gelap'] as $label) {
            $this->assertStringContainsString('<span class="visually-hidden">'.$label.'</span>', $form[1]);
        }
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
        $this->assertFollowsOs($page);
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

    /** Tema dan entri auditnya jadi atau batal bersama (docs/21): rantai audit yang terkunci menggagalkan keduanya. */
    public function test_theme_is_not_saved_when_its_audit_entry_cannot_be_written(): void
    {
        config(['database.connections.penulis_lain' => config('database.connections.pgsql')]);
        $other = DB::connection('penulis_lain');
        $other->beginTransaction();
        $other->select('SELECT pg_advisory_xact_lock(?)', [AppendAuditEntry::CHAIN_LOCK_KEY]);
        DB::statement("SET lock_timeout = '300ms'");

        try {
            app(UpdateThemePreference::class)->handle($this->admin, ThemePreference::Dark);
            $this->fail('Perubahan tema seharusnya gagal selama rantai audit dikunci penulis lain.');
        } catch (QueryException $e) {
            $this->assertSame('55P03', $e->getCode());
        } finally {
            $other->rollBack();
            $other->disconnect();
        }

        $this->assertSame('system', DB::table('admins')->where('id', $this->admin->id)->value('theme'));
        $this->assertSame(ThemePreference::System, $this->admin->theme);
        $this->assertSame(0, DB::table('audit_entries')->count());
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
        $this->assertFollowsOs($page);
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
     * Skrip `system` (kedua layout): terapkan mode OS saat dimuat dan ikuti bila OS berganti mode.
     *
     * @param  TestResponse<Response>  $page
     */
    private function assertFollowsOs(TestResponse $page): void
    {
        $page->assertSee("window.matchMedia('(prefers-color-scheme: dark)')", false)
            ->assertSee("setAttribute('data-bs-theme', media.matches ? 'dark' : 'light')", false)
            ->assertSee('apply();', false)
            ->assertSee("media.addEventListener('change', apply);", false);
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
        // Pilihan aktif bergaya primer (warna token), yang lain tidak.
        $this->assertCount(1, array_filter($buttons[0], fn (string $button): bool => str_contains($button, 'btn-primary')));
        $this->assertStringContainsString('btn-primary', $pressed[0]);
        $this->assertSame(1, preg_match('/\bvalue="([^"]*)"/', $pressed[0], $value));

        return $value[1];
    }
}

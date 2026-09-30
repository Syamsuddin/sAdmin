<?php

namespace Tests\Feature;

use Illuminate\Support\Facades\Route;
use Tests\TestCase;

/**
 * Laravel 13 menyajikan disk `local` lewat rute storage/{path} (GET, dan PUT unggah bertanda tangan) bila
 * `serve` aktif. Console sAdmin tak menyajikan atau menerima berkas lewat rute itu, jadi permukaannya ditutup.
 */
class StorageRoutesTest extends TestCase
{
    public function test_local_disk_is_not_served_over_http(): void
    {
        $this->assertFalse(Route::has('storage.local'));
        $this->assertFalse(Route::has('storage.local.upload'));
        $this->get('/storage/berkas.txt')->assertNotFound();
        $this->put('/storage/berkas.txt', ['isi' => 'x'])->assertNotFound();
    }
}

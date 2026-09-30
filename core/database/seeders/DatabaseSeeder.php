<?php

namespace Database\Seeders;

use App\Models\Tenant;
use Illuminate\Database\Seeder;

class DatabaseSeeder extends Seeder
{
    /**
     * MVP berisi satu tenant (docs/07); produksi membuatnya lewat install.sh.
     */
    public function run(): void
    {
        Tenant::query()->firstOrCreate(['name' => 'Instansi Contoh']);
    }
}

<?php

namespace Tests;

use Illuminate\Foundation\Testing\TestCase as BaseTestCase;

abstract class TestCase extends BaseTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // Aset Vite tak dibangun saat tes; tampilan dirender tanpa manifest.
        $this->withoutVite();
    }
}

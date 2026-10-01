<?php

namespace App\Domain\Audit\Data;

/** Akhir satu percobaan membuat checkpoint (ADR 0004 §2.4). */
enum CheckpointStatus: string
{
    case Created = 'created';
    case NothingNew = 'nothing_new';
    case NotDue = 'not_due';
    /** Rantai atau checkpoint terakhir terbukti rusak: tak ditandatangani, audit_mismatch critical. */
    case Refused = 'refused';
    /** Prasyarat belum ada (instansi, kunci audit): tak ditandatangani, log error. */
    case Unavailable = 'unavailable';
}

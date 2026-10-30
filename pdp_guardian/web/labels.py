"""Bahasa Indonesia labels for the keys and reasons stored (in English) in evidence.

Only labels are translated. Stored values are shown exactly as hashed, so a DPO
can compare the page with the record.
"""

from datetime import datetime, timedelta, timezone

from pdp_guardian.checks import Status

WIB = timezone(timedelta(hours=7), "WIB")  # Indonesia has no daylight saving time

COUNT_LABELS: dict[str, str] = {
    "scanned": "Nilai / entri diperiksa",
    "opaque": "Nilai tampak terenkripsi atau di-hash",
    "retention_days": "Retensi dideklarasikan (hari)",
    "row_count": "Jumlah baris",
    "rows_before_cutoff": "Baris melewati batas retensi",
    "null_rows": "Baris tanpa nilai waktu (NULL)",
    "found_types": "Jenis data ditemukan",
    "declared_types": "Jenis data dideklarasikan",
    "undeclared_types": "Jenis data tidak dideklarasikan",
    "limit": "Batas entri log",
    "data_types": "Jumlah jenis data pribadi",
}

DETAIL_LABELS: dict[str, str] = {
    "category": "Kategori",
    "cutoff": "Batas retensi",
    "timestamp_column": "Kolom waktu",
    "oldest": "Data tertua",
    "data_types": "Jenis data",
    "undeclared_types": "Jenis data tidak dideklarasikan",
    "declared_not_found": "Dideklarasikan, tidak ditemukan",
    "since": "Log diperiksa sejak",
    "location": "Lokasi",
    "note": "Catatan teknis",
    "error": "Galat pemindaian",
}

CHAIN_REASONS: dict[str, str] = {
    "sequence gap or reordering": "urutan record terputus atau berubah",
    "prev_hash does not link": "prev_hash tidak tersambung ke record sebelumnya",
    "content does not match hash": "isi record tidak cocok dengan hash-nya",
}


def count_label(key: str) -> str:
    # Data type keys (NIK, KK, NPWP, ...) hold detector hits.
    return COUNT_LABELS.get(key, f"Hit {key}" if key.isupper() else key)


def detail_label(key: str) -> str:
    return DETAIL_LABELS.get(key, key)


def chain_reason(reason: str | None) -> str:
    return CHAIN_REASONS.get(reason or "", reason or "")


def status_class(status: Status | None) -> str:
    """CSS modifier: pass, fail, needs-review, not-assessed (or none)."""
    return status.value.lower().replace("_", "-") if status else "none"


def wib(moment: datetime) -> str:
    return f"{moment.astimezone(WIB):%d-%m-%Y %H:%M:%S} WIB"

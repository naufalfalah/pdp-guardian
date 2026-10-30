"""Template narrator: plain Bahasa Indonesia from an evidence record.

Deterministic and offline, so the demo never depends on an LLM. It only reads a
record; it never decides or changes a status. Every sentence carries the
record's evidence ID. Wording describes findings for a DPO to review and never
claims a verdict.
"""

from collections.abc import Callable
from dataclasses import dataclass

from pdp_guardian.checks import CHECK_TITLES, Status
from pdp_guardian.evidence import EvidenceRecord

DISCLAIMER = "Temuan untuk ditinjau DPO; bukan pernyataan kesesuaian."

STATUS_LABELS: dict[Status, str] = {
    Status.PASS: "Lolos cek",
    Status.FAIL: "Gagal cek",
    Status.NEEDS_REVIEW: "Perlu ditinjau",
    Status.NOT_ASSESSED: "Belum dinilai",
}

# English notes stored in evidence ``details`` -> UI wording.
_NOTES: dict[str, str] = {
    "encryption strength not assessed": (
        "Nilainya tampak terenkripsi atau di-hash; kekuatan enkripsinya tidak dinilai."
    ),
    "values are neither plaintext identifiers nor ciphertext-like; format not assessed": (
        "Nilainya bukan nomor identitas teks biasa dan tidak tampak seperti ciphertext; "
        "formatnya tidak dinilai."
    ),
    "no non-null values sampled": "Tidak ada nilai (non-NULL) yang bisa diambil sampelnya.",
    "timestamp column not declared": (
        "Deklarasi tidak menyebut kolom waktu untuk lokasi ini, jadi umur data tidak bisa diukur."
    ),
    "table is empty": "Tabel kosong.",
    "some rows have no timestamp": "Sebagian baris tidak memiliki nilai waktu (NULL).",
    "resource not in inventory": "Sumber data yang dideklarasikan tidak ditemukan saat inventaris.",
    "no log entries in the window": "Tidak ada entri log dalam jendela waktu scan.",
    "entry limit reached; older entries in the window were not scanned": (
        "Batas jumlah entri tercapai; entri yang lebih lama dalam jendela tidak diperiksa."
    ),
    "location unknown": "Lokasi (region) sumber data tidak diketahui.",
}


@dataclass(frozen=True, slots=True)
class Narrative:
    evidence_id: str
    status: Status  # always the record's status, copied, never derived
    title: str
    summary: str
    remediation: str | None


def narrate(record: EvidenceRecord) -> Narrative:
    sentences, remediation = _TEMPLATES[record.check_id](record)
    note = record.details.get("note")
    if note:
        sentences.append(_NOTES.get(note, f"Catatan teknis: {note}."))
    error = record.details.get("error")
    if error:
        sentences.append(f"Pemindaian gagal ({error}); tidak ada kesimpulan yang diambil.")
    tag = f"[{record.evidence_id}]"
    return Narrative(
        evidence_id=record.evidence_id,
        status=record.status,
        title=CHECK_TITLES[record.check_id],
        summary=" ".join(f"{tag} {sentence}" for sentence in sentences),
        remediation=f"{tag} {remediation}" if remediation else None,
    )


def _where(record: EvidenceRecord) -> str:
    if record.locator in ("*", "payload"):
        return record.resource
    return f"kolom {record.locator} di {record.resource}"


def _c1(record: EvidenceRecord) -> tuple[list[str], str | None]:
    c = record.counts
    scanned = c.get("scanned", 0)
    if record.status is Status.FAIL:
        types = record.details.get("data_types", "")
        hits = max((c.get(t.strip(), 0) for t in types.split(",")), default=0)
        return (
            [
                f"Di {_where(record)}, {hits} dari {scanned} nilai sampel "
                f"({hits / scanned:.0%}) terbaca sebagai {types} dalam bentuk teks biasa.",
            ],
            "Enkripsi atau pseudonimisasi kolom ini (misalnya pgcrypto atau enkripsi di aplikasi "
            "dengan kunci di KMS), lalu jalankan scan ulang.",
        )
    if record.status is Status.PASS:
        hits = max((n for k, n in c.items() if k not in ("scanned", "opaque")), default=0)
        return (
            [
                f"Di {_where(record)}, {hits} dari {scanned} nilai sampel terbaca sebagai nomor "
                "identitas dalam bentuk teks biasa, di bawah ambang temuan."
            ],
            None,
        )
    return ([f"Kolom identitas di {_where(record)} belum dapat dinilai."], None)


def _c2(record: EvidenceRecord) -> tuple[list[str], str | None]:
    c, d = record.counts, record.details
    category, days = d.get("category", "?"), c.get("retention_days", 0)
    head = f"Kategori {category} di {record.resource} (retensi dideklarasikan {days} hari)"
    if record.status is Status.FAIL:
        return (
            [
                f"{head}: {c['rows_before_cutoff']} dari {c['row_count']} baris lebih tua dari "
                f"batas retensi; data tertua tercatat {d.get('oldest', '?')}.",
            ],
            "Musnahkan atau anonimkan baris yang melewati masa retensi, lalu jadwalkan "
            "pembersihan rutin sesuai deklarasi.",
        )
    if record.status is Status.PASS:
        return ([f"{head}: tidak ada baris yang melewati batas retensi."], None)
    if record.status is Status.NEEDS_REVIEW:
        return (
            [f"{head}: {c.get('null_rows', 0)} baris tidak bisa diukur umurnya."],
            "Isi kolom waktu yang kosong atau tinjau baris tersebut secara manual.",
        )
    return ([f"{head}: retensi belum dapat dinilai."], None)


def _c3(record: EvidenceRecord) -> tuple[list[str], str | None]:
    d = record.details
    sentences, remediation = [], None
    if record.status is Status.FAIL:
        sentences.append(
            f"Di {record.resource} ditemukan {d['undeclared_types']} yang tidak tercatat di "
            "deklarasi pemrosesan."
        )
        remediation = (
            "Tambahkan lokasi dan jenis data ini ke declaration.yaml beserta tujuan dan masa "
            "retensinya, atau hapus data jika tidak diperlukan."
        )
    elif record.status is Status.PASS:
        sentences.append(
            f"Semua jenis data yang ditemukan di {record.resource} sudah dideklarasikan."
        )
    else:
        sentences.append(f"Lokasi {record.resource} dideklarasikan tetapi tidak dapat dipindai.")
    if "declared_not_found" in d:
        sentences.append(
            f"Peringatan: {d['declared_not_found']} dideklarasikan tetapi tidak ditemukan "
            "dalam sampel."
        )
    return sentences, remediation


def _c4(record: EvidenceRecord) -> tuple[list[str], str | None]:
    c, d = record.counts, record.details
    since = d.get("since", "?")
    if record.status is Status.FAIL:
        return (
            [
                f"Log {record.resource} sejak {since} memuat {d.get('data_types', '')} "
                f"(dari {c.get('scanned', 0)} entri yang diperiksa).",
            ],
            "Hapus atau samarkan data pribadi sebelum ditulis ke log (misalnya filter logging), "
            "lalu atur retensi log yang sudah terlanjur memuatnya.",
        )
    if record.status is Status.PASS:
        return (
            [
                f"Tidak ada data pribadi di {c.get('scanned', 0)} entri log {record.resource} "
                f"sejak {since}."
            ],
            None,
        )
    return ([f"Log {record.resource} belum dapat dinilai."], None)


def _c5(record: EvidenceRecord) -> tuple[list[str], str | None]:
    d = record.details
    location = d.get("location", "tidak diketahui")
    sentence = (
        f"{record.resource} menyimpan {d.get('data_types', 'data pribadi')} di lokasi {location}."
    )
    if record.status is Status.PASS:
        return ([sentence + " Lokasi ini berada di Indonesia."], None)
    return (
        [
            sentence + " Transfer ke luar Indonesia sah hanya dengan syarat tertentu yang tidak "
            "dapat dilihat oleh pemindai."
        ],
        "Pastikan dasar transfer lintas negara terdokumentasi, atau pindahkan data ke region "
        "Indonesia (misalnya asia-southeast2).",
    )


_TEMPLATES: dict[str, Callable[[EvidenceRecord], tuple[list[str], str | None]]] = {
    "C1": _c1,
    "C2": _c2,
    "C3": _c3,
    "C4": _c4,
    "C5": _c5,
}

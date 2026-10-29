"""The single mapping from checks to regulation articles.

[VERIFY] Every reference below comes from secondary sources. Check each against
the official PP 33/2026 and UU 27/2022 text (JDIH / peraturan.go.id), then set
``verified=True``. Correct it here and nowhere else.
"""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Article:
    label: str  # stored in evidence records, e.g. "PP 33/2026 Pasal 123"
    title: str  # Bahasa Indonesia, shown in the UI
    verified: bool = False


# Display order for reports and the dashboard.
ARTICLES: tuple[Article, ...] = (
    Article("PP 33/2026 Pasal 123", "Pseudonimisasi dan enkripsi data pribadi"),
    Article("PP 33/2026 Pasal 75 & 86", "Masa retensi dan pemusnahan data pribadi"),
    Article("PP 33/2026 Pasal 74", "Rekaman aktivitas pemrosesan data pribadi"),
    Article("UU PDP Pasal 56", "Transfer data pribadi ke luar wilayah hukum Indonesia"),
)

_BY_LABEL = {article.label: article for article in ARTICLES}

CHECK_ARTICLES: dict[str, str] = {
    "C1": "PP 33/2026 Pasal 123",
    "C2": "PP 33/2026 Pasal 75 & 86",
    "C3": "PP 33/2026 Pasal 74",
    "C4": "PP 33/2026 Pasal 123",
    "C5": "UU PDP Pasal 56",
}

CHECK_TITLES: dict[str, str] = {
    # Neutral subjects, not findings: they sit next to every status, PASS included.
    "C1": "Enkripsi kolom nomor identitas",
    "C2": "Masa retensi data",
    "C3": "Lokasi data di deklarasi pemrosesan",
    "C4": "Data pribadi di log aplikasi",
    "C5": "Lokasi penyimpanan data pribadi",
}


def article_for(check_id: str) -> Article:
    """The article a check produces evidence for. Raises ``KeyError`` on unknown checks."""
    return _BY_LABEL[CHECK_ARTICLES[check_id]]

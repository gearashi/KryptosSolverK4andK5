"""Public Kryptos inputs and explicit provenance; no claimed K4/K5 solution.

Crib positions are ONE-BASED offsets into the 97-letter K4 plaintext.  The
question mark preceding OBKR on the sculpture is not included in this target.
"""

K4_CIPHERTEXT = (
    "OBKR"
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO"
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP"
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
)

K4_CRIBS = [
    {"start": 22, "text": "EAST"},
    {"start": 26, "text": "NORTHEAST"},
    {"start": 64, "text": "BERLIN"},
    {"start": 70, "text": "CLOCK"},
]

# These are heuristic search seeds, NOT confirmed keys for K4 or K5.
DEFAULT_KEYS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK", "BERLINCLOCK",
    "EAST", "NORTHEAST", "EASTNORTHEAST", "WORLDCLOCK", "WELTZEITUHR",
    "ALEXANDERPLATZ", "SHADOW", "LIGHT", "ILLUSION", "IQLUSION",
    "MAGNETIC", "UNDERGROUND", "UNDERGRUUND", "MESSAGE", "DELIVERING",
    "EGYPT", "CARTER", "TUTANKHAMUN", "LANGLEY", "WEBSTER", "SANBORN",
    "SCHEIDT", "INVISIBLE", "SLOWLY", "DESPERATELY", "VIRTUALLYINVISIBLE",
]

# No authenticated public K5 ciphertext was located in the sources reviewed.
# A K5 experiment must supply and label its own target; never reuse K4 silently.
K5_CIPHERTEXT = None
K5_CRIBS = []

SOURCES = [
    {
        "id": "cia-transcript",
        "title": "CIA Kryptos printable transcription",
        "url": "https://www.cia.gov/spy-kids/games/images/KryptosPrint.pdf",
        "kind": "primary institutional transcription",
        "supports": "K4 letters: last 97 letters of Panel 2; cross-checked with Dunin.",
    },
    {
        "id": "dunin-transcript",
        "title": "Elonka Dunin: Kryptos transcript",
        "url": "https://www.elonka.com/kryptos/transcript.html",
        "kind": "researcher's sculpture transcription",
        "supports": "Independent corroboration of the 97-letter K4 transcription.",
    },
    {
        "id": "dunin-clues",
        "title": "Elonka Dunin: Kryptos and the released plaintext clues",
        "url": "https://www.elonka.com/kryptos/",
        "kind": "researcher and community moderator's clue record",
        "supports": "BERLIN (2010), CLOCK (2014), NORTHEAST and EAST (2020).",
    },
    {
        "id": "sanborn-2025-letter",
        "title": "Jim Sanborn's August 2025 open letter",
        "url": "https://www.elonka.com/kryptos/OpenLetterAug2025.html",
        "kind": "primary artist statement, hosted by Dunin",
        "supports": "K4 stewardship transfer and an additional riddle called K5.",
    },
    {
        "id": "rr-auction-archive",
        "title": "RR Auction: complete Kryptos archive, lot 2001",
        "url": "https://www.rrauction.com/auctions/lot-detail/350761607302001-the-complete-secrets-of-kryptos-jim-sanborns-private-archive/",
        "kind": "primary auction record",
        "supports": "Private K4 system; K5 described as an unpublished 1988 alternate K4 text and chart.",
    },
    {
        "id": "rr-auction-result",
        "title": "RR Auction: Kryptos archive sale result, November 21, 2025",
        "url": "https://content.rrauction.com/jim-sanborns-complete-kryptos-archive-sells-for-962500-at-auction/",
        "kind": "primary auction result",
        "supports": "Archive including K4/K5 material sold November 20, 2025, for $962,500.",
    },
    {
        "id": "sanborn-november-clues",
        "title": "Scientific American: Sanborn's November 2025 talk and clues",
        "url": "https://www.scientificamerican.com/article/cia-kryptos-puzzle-creator-releases-final-clues/",
        "kind": "eyewitness reporting of the artist's talk and open letter",
        "supports": "World Clock referent, Egypt and Berlin Wall context, message delivery, and K2/K5 theme.",
    },
    {
        "id": "boinc-launch",
        "title": "Kryptos@Home January 2021 project announcement",
        "url": "https://www.reddit.com/r/BOINC/comments/kui7xc/",
        "kind": "contemporaneous project announcement",
        "supports": "Existence and purpose of the earlier volunteer computing project.",
    },
    {
        "id": "paradigm-stewardship",
        "title": "Paradigm: Project Kryptos, June 12, 2026",
        "url": "https://www.paradigm.xyz/writing/kryptos",
        "kind": "primary current-owner statement",
        "supports": "Stewardship, private SHA256-to-KMS-HMAC verifier, and future release of a 97-character K5 ciphertext.",
    },
    {
        "id": "paradigm-k4",
        "title": "Paradigm: K4 target and submission interface",
        "url": "https://www.paradigm.xyz/kryptos/k4",
        "kind": "primary current-owner public site and linked client script",
        "supports": "Current unsolved label, 97 uppercase A-Z input, crib checks, and paid form submission.",
    },
]

K4_VERIFIER = {
    "owner": "Paradigm",
    "url": "https://www.paradigm.xyz/kryptos/k4",
    "checked_on": "2026-10-12",
    "public_plaintext_sha256": None,
    "offline_digest_check_available": False,
    "owner_described_setup": "SHA256 of Sanborn's input, then HMAC using Google Cloud KMS",
    "client_format": "Exactly 97 ASCII A-Z letters; each grid cell is uppercased and non-A-Z characters removed.",
    "client_checks": "Exact K4 crib matches; name, email, and decryption method required.",
    "submission": "Paid form; no candidate, payment, or personal information has been submitted by this project.",
    "limits": "No public target digest found; server normalization and HMAC key not established by client inspection.",
    "client_script_url": "https://www.paradigm.xyz/kryptos/_next/static/chunks/9308b667190255e3.js?dpl=dpl_B7wJQfFhM37xL7YHvMX31rRPiBah",
    "client_script_utf8_sha256": "274a0f90d5fd0cc8508017b2319719aa6d63bf9f64507a39b268e6defe33e3f6",
}

KNOWLEDGE = {
    "checked_on": "2026-10-12",
    "status": (
        "K4 research target: 97 ciphertext letters and 24 publicly released plaintext letters. "
        "Archival recovery of the text in 2025 is distinct from a reproducible cryptanalytic solution. "
        "The current steward Paradigm still labels K4 unsolved. "
        "No authenticated public full decryption method was located in this source review."
    ),
    "k5_status": (
        "In June 2026 Paradigm said Sanborn supplied another 97-character K5 ciphertext "
        "for future release. The 2025 auction called its K5 material an alternate K4 text/chart. "
        "No authenticated public K5 ciphertext was located. K5 runs require an explicit hypothesis."
    ),
    "position_convention": "1-based, including both ends; starts 22, 26, 64, 70",
    "sources": SOURCES,
    "verification": K4_VERIFIER,
    "notes": [
        "A high English score or all 24 crib matches is a candidate, not a confirmed solution.",
        "Every candidate needs a specified reproducible transform, key, and exact re-encryption.",
        "Search seeds, cipher families, reading routes, and extraction rules are hypotheses.",
        "Do not transfer K4 cribs to a user-supplied K5 target without justification.",
        "Sanborn's November 2025 clues identify the World Clock in Berlin as the clock referent.",
        "This application is independent of the former Kryptos@Home server and has no imported results.",
        "A completed finite search only covers its recorded bounds and assumptions.",
    ],
}

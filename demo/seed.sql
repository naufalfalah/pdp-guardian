-- PT Kopi Senja: a fictional coffee chain used as the PDP Guardian demo company.
--
-- SYNTHETIC DATA ONLY. NIKs are generated to be structurally valid (real region
-- codes, plausible birth dates) but belong to nobody; names, phone numbers, and
-- emails are made up. Generation is deterministic, so a local Postgres and Cloud
-- SQL seeded from this file hold identical rows (the demo fallback depends on it).
--
-- What the first scan should find (see tests/test_demo.py):
--   C1  customers.nik is plaintext NIK                          -> FAIL  (Pasal 123)
--   C2  11 of 200 customers are older than the declared 730 days -> FAIL  (Pasal 75 & 86)
--   C3  marketing_leads holds NAME/PHONE/EMAIL, not declared      -> FAIL  (Pasal 74)
--   C5  every table is in asia-southeast2                         -> PASS  (Pasal 56)
-- demo/migrate_encrypt_nik.sql then flips C1 to PASS.
--
-- Run as the database owner. demo/reset.sh does this, plus the read-only role.

DROP TABLE IF EXISTS orders, marketing_leads, customers CASCADE;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE customers (
    id         integer PRIMARY KEY,
    nik        text NOT NULL,
    nama       text NOT NULL,
    no_hp      text NOT NULL,
    alamat     text NOT NULL,
    created_at timestamptz NOT NULL
);

-- NIK = region (6) + DDMMYY birth date, day + 40 for women (6) + serial (4).
INSERT INTO customers (id, nik, nama, no_hp, alamat, created_at)
SELECT
    i,
    (ARRAY['320101', '327301', '327101', '317101', '317401', '340101'])[1 + i % 6]
        || lpad((1 + (i * 7) % 28 + CASE WHEN i % 2 = 0 THEN 40 ELSE 0 END)::text, 2, '0')
        || lpad((1 + (i * 5) % 12)::text, 2, '0')
        || lpad((60 + (i * 3) % 40)::text, 2, '0')
        || lpad(i::text, 4, '0'),
    (ARRAY['Budi', 'Siti', 'Andi', 'Dewi', 'Rizky', 'Putri', 'Agus', 'Rina', 'Fajar', 'Lestari'])
        [1 + i % 10]
        || ' '
        || (ARRAY['Santoso', 'Aminah', 'Wijaya', 'Lestari', 'Pratama', 'Hidayat', 'Saputra'])
        [1 + (i * 3) % 7],
    '08' || (ARRAY['11', '12', '13', '21', '52', '57', '78', '96'])[1 + i % 8]
        || lpad(((i * 7919) % 100000000)::text, 8, '0'),
    'Jl. ' || (ARRAY['Merdeka', 'Sukajadi', 'Dago', 'Braga', 'Malioboro', 'Cikini'])[1 + i % 6]
        || ' No. ' || (1 + i % 120) || ', '
        || (ARRAY['Bogor', 'Bandung', 'Bandung', 'Jakarta', 'Jakarta', 'Yogyakarta'])[1 + i % 6],
    -- Every 17th customer (11 rows) is 817-987 days old; the rest are under 700 days.
    now() - make_interval(
        days => CASE WHEN i % 17 = 0 THEN 800 + i ELSE (i * 13) % 700 END,
        hours => i % 24
    )
FROM generate_series(1, 200) AS i;

-- Not in declaration.yaml: the marketing team's own lead list.
CREATE TABLE marketing_leads (
    id         integer PRIMARY KEY,
    nama       text NOT NULL,
    no_hp      text NOT NULL,
    email      text NOT NULL,
    sumber     text NOT NULL,
    created_at timestamptz NOT NULL
);

INSERT INTO marketing_leads (id, nama, no_hp, email, sumber, created_at)
SELECT
    i,
    (ARRAY['Rani', 'Yoga', 'Intan', 'Bayu', 'Maya'])[1 + i % 5]
        || ' ' || (ARRAY['Kusuma', 'Nugroho', 'Permata', 'Siregar'])[1 + (i * 3) % 4],
    '0813' || lpad(((i * 104729) % 100000000)::text, 8, '0'),
    'lead' || i || '@example.com',
    (ARRAY['instagram', 'event', 'website'])[1 + i % 3],
    now() - make_interval(days => i % 60)
FROM generate_series(1, 50) AS i;

-- No personal data: must produce no findings at all.
CREATE TABLE orders (
    id          integer PRIMARY KEY,
    customer_id integer NOT NULL REFERENCES customers (id),
    menu        text NOT NULL,
    total       integer NOT NULL,
    status      text NOT NULL,
    created_at  timestamptz NOT NULL
);

INSERT INTO orders (id, customer_id, menu, total, status, created_at)
SELECT
    i,
    1 + (i * 37) % 200,
    (ARRAY['Kopi Susu Senja', 'Americano', 'Es Kopi Aren', 'Matcha Latte'])[1 + i % 4],
    (ARRAY[25000, 20000, 22000, 28000])[1 + i % 4],
    (ARRAY['paid', 'paid', 'paid', 'refunded'])[1 + i % 4],
    now() - make_interval(days => i % 90)
FROM generate_series(1, 300) AS i;

-- Live demo step: encrypt customers.nik with pgcrypto, then re-scan.
-- C1 (Pasal 123) flips from FAIL to PASS, noted "encryption strength not assessed".
--
-- HACKATHON: the key is a literal so the demo runs with one command. Production
-- would fetch it from Secret Manager / Cloud KMS at runtime and never write it in SQL.

DO $$
BEGIN
    IF (SELECT data_type FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'customers' AND column_name = 'nik')
        IS DISTINCT FROM 'text' THEN
        RAISE EXCEPTION 'customers.nik is not plaintext text; run demo/reset.sh first';
    END IF;

    ALTER TABLE customers
        ALTER COLUMN nik TYPE bytea USING pgp_sym_encrypt(nik, 'kopi-senja-demo-key');
END $$;

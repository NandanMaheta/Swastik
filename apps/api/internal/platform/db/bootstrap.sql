-- Idempotent bootstrap run by db.Migrate before goose. PostgreSQL 17 has no uuidv7(); PostgreSQL 18
-- ships one in pg_catalog. Define our own (RFC 9562 v7) only when neither exists, so on 18 this is a no-op.
DO $bootstrap$
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext('swastik.bootstrap.uuidv7'));
  IF NOT EXISTS (
    SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE p.proname = 'uuidv7' AND n.nspname IN ('pg_catalog', 'public') AND p.pronargs = 0
  ) THEN
    -- 48-bit unix ms timestamp, then a random v4 uuid whose version nibble is flipped 4 -> 7.
    -- The variant bits (10) are already set by gen_random_uuid().
    CREATE FUNCTION public.uuidv7() RETURNS uuid
    LANGUAGE sql VOLATILE PARALLEL SAFE
    AS $fn$
      SELECT encode(
        set_bit(set_bit(
          overlay(uuid_send(gen_random_uuid())
                  PLACING substring(int8send(floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint) FROM 3)
                  FROM 1 FOR 6),
          52, 1), 53, 1),
        'hex')::uuid
    $fn$;
  END IF;
END
$bootstrap$;

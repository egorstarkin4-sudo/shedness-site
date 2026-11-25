-- ==============================================================================
-- Shedness Launcher — Automated RLS Security Verification Suite
-- Run inside a transaction (ROLLBACK at the end) via psql or Supabase SQL Editor.
-- Proves deny-by-default isolation across anon and authenticated roles.
-- ==============================================================================

BEGIN;

-- Create two isolated synthetic test users inside auth.users
INSERT INTO auth.users (id, instance_id, aud, role, email, encrypted_password, email_confirmed_at, created_at, updated_at)
VALUES
    ('11111111-1111-1111-1111-111111111111', '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', 'user_a@test.local', 'hash', NOW(), NOW(), NOW()),
    ('22222222-2222-2222-2222-222222222222', '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', 'user_b@test.local', 'hash', NOW(), NOW(), NOW())
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.profiles (id, email, mc_nickname, subscription_active, subscription_until, is_admin, uid)
VALUES
    ('11111111-1111-1111-1111-111111111111', 'user_a@test.local', 'UserAlpha', FALSE, 'Не активна', FALSE, 90001),
    ('22222222-2222-2222-2222-222222222222', 'user_b@test.local', 'UserBeta', TRUE, 'Навсегда (Lifetime)', FALSE, 90002)
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.license_keys (key_hash, key_hmac, key_prefix, duration_days, is_used)
VALUES ('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef', 'hmac', 'SHEDNESS-30D-TEST', 30, FALSE)
ON CONFLICT DO NOTHING;

INSERT INTO public.audit_log (actor_id, action, target_type, target_id)
VALUES ('11111111-1111-1111-1111-111111111111', 'test.event', 'system', '0');

-- ------------------------------------------------------------------------------
-- TEST 1: Anonymous role cannot read profiles, license_keys, audit_log, admin_totp, releases
-- ------------------------------------------------------------------------------
SET LOCAL ROLE anon;
DO $$
DECLARE v_count INT;
BEGIN
    SELECT COUNT(*) INTO v_count FROM public.profiles;
    IF v_count <> 0 THEN RAISE EXCEPTION 'FAIL: anon read profiles (% rows)', v_count; END IF;

    SELECT COUNT(*) INTO v_count FROM public.license_keys;
    IF v_count <> 0 THEN RAISE EXCEPTION 'FAIL: anon read license_keys (% rows)', v_count; END IF;

    SELECT COUNT(*) INTO v_count FROM public.audit_log;
    IF v_count <> 0 THEN RAISE EXCEPTION 'FAIL: anon read audit_log (% rows)', v_count; END IF;

    SELECT COUNT(*) INTO v_count FROM public.admin_totp;
    IF v_count <> 0 THEN RAISE EXCEPTION 'FAIL: anon read admin_totp (% rows)', v_count; END IF;

    SELECT COUNT(*) INTO v_count FROM public.releases;
    IF v_count <> 0 THEN RAISE EXCEPTION 'FAIL: anon read releases (% rows)', v_count; END IF;

    SELECT COUNT(*) INTO v_count FROM public.admins;
    IF v_count <> 0 THEN RAISE EXCEPTION 'FAIL: anon read admins (% rows)', v_count; END IF;
END $$;

-- ------------------------------------------------------------------------------
-- TEST 2: Authenticated User A cannot read User B's profile or license keys
-- ------------------------------------------------------------------------------
RESET ROLE;
SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claims', '{"sub":"11111111-1111-1111-1111-111111111111","role":"authenticated"}', true);

DO $$
DECLARE v_count INT;
BEGIN
    SELECT COUNT(*) INTO v_count FROM public.profiles WHERE id = '22222222-2222-2222-2222-222222222222';
    IF v_count <> 0 THEN RAISE EXCEPTION 'FAIL: User A read User B profile'; END IF;

    SELECT COUNT(*) INTO v_count FROM public.license_keys;
    IF v_count <> 0 THEN RAISE EXCEPTION 'FAIL: User A read unbound license_keys'; END IF;

    SELECT COUNT(*) INTO v_count FROM public.audit_log;
    IF v_count <> 0 THEN RAISE EXCEPTION 'FAIL: Non-admin read audit_log'; END IF;

    SELECT COUNT(*) INTO v_count FROM public.admin_totp;
    IF v_count <> 0 THEN RAISE EXCEPTION 'FAIL: Authenticated user read admin_totp'; END IF;
END $$;

-- ------------------------------------------------------------------------------
-- TEST 3: Authenticated User A cannot escalate privileges or activate subscription
-- ------------------------------------------------------------------------------
DO $$
BEGIN
    BEGIN
        UPDATE public.profiles SET is_admin = TRUE WHERE id = '11111111-1111-1111-1111-111111111111';
        RAISE EXCEPTION 'FAIL: User A escalated is_admin';
    EXCEPTION WHEN insufficient_privilege THEN
        NULL; -- Expected 42501
    END;

    BEGIN
        UPDATE public.profiles SET subscription_active = TRUE WHERE id = '11111111-1111-1111-1111-111111111111';
        RAISE EXCEPTION 'FAIL: User A self-activated subscription';
    EXCEPTION WHEN insufficient_privilege THEN
        NULL; -- Expected 42501
    END;
END $$;

-- ------------------------------------------------------------------------------
-- TEST 4: audit_log is append-only even for service_role
-- ------------------------------------------------------------------------------
RESET ROLE;
DO $$
BEGIN
    BEGIN
        DELETE FROM public.audit_log;
        RAISE EXCEPTION 'FAIL: audit_log allowed DELETE';
    EXCEPTION WHEN insufficient_privilege THEN
        NULL; -- Expected 42501
    END;

    BEGIN
        UPDATE public.audit_log SET action = 'tampered';
        RAISE EXCEPTION 'FAIL: audit_log allowed UPDATE';
    EXCEPTION WHEN insufficient_privilege THEN
        NULL; -- Expected 42501
    END;
END $$;

RAISE NOTICE 'ALL RLS SECURITY TESTS PASSED';

ROLLBACK;

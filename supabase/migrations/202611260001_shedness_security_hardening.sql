-- ==============================================================================
-- Shedness Launcher — Security Hardening & Feature Migration
-- Compatible with existing /ne schema (profiles, license_keys, admins, site_config)
-- ==============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ==============================================================================
-- 1. Admins Allowlist Table (Zero hardcoded emails in code)
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.admins (
    user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.admins
    ADD COLUMN IF NOT EXISTS email TEXT,
    ADD COLUMN IF NOT EXISTS note TEXT,
    ADD COLUMN IF NOT EXISTS created_by UUID REFERENCES auth.users(id);

ALTER TABLE public.admins ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE r RECORD;
BEGIN
    FOR r IN (SELECT policyname FROM pg_policies WHERE tablename = 'admins' AND schemaname = 'public') LOOP
        EXECUTE format('DROP POLICY IF EXISTS %I ON public.admins;', r.policyname);
    END LOOP;
END $$;

-- Authenticated users can only check whether THEIR OWN user_id is in admins
CREATE POLICY "admins_select_self" ON public.admins
    FOR SELECT
    TO authenticated
    USING (auth.uid() = user_id);

-- Strict server-enforced admin check (no hardcoded emails, no profile fallback)
CREATE OR REPLACE FUNCTION public.is_admin()
RETURNS BOOLEAN AS $$
DECLARE
    v_uid UUID := auth.uid();
BEGIN
    IF v_uid IS NULL THEN
        RETURN FALSE;
    END IF;

    RETURN EXISTS (
        SELECT 1 FROM public.admins a
        WHERE a.user_id = v_uid
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER STABLE SET search_path = public;

REVOKE ALL ON FUNCTION public.is_admin() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.is_admin() FROM anon;
GRANT EXECUTE ON FUNCTION public.is_admin() TO authenticated, service_role;

-- ==============================================================================
-- 2. Profiles Table Hardening (Compatible with /ne)
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email TEXT,
    mc_nickname TEXT,
    hwid TEXT,
    subscription_active BOOLEAN NOT NULL DEFAULT FALSE,
    subscription_until TEXT DEFAULT 'Не активна',
    is_admin BOOLEAN NOT NULL DEFAULT FALSE,
    uid BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.profiles
    ADD COLUMN IF NOT EXISTS avatar_url TEXT,
    ADD COLUMN IF NOT EXISTS subscription_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS is_banned BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE r RECORD;
BEGIN
    FOR r IN (SELECT policyname FROM pg_policies WHERE tablename = 'profiles' AND schemaname = 'public') LOOP
        EXECUTE format('DROP POLICY IF EXISTS %I ON public.profiles;', r.policyname);
    END LOOP;
END $$;

CREATE POLICY "profiles_select_self" ON public.profiles
    FOR SELECT
    TO authenticated
    USING (auth.uid() = id);

CREATE POLICY "profiles_select_admin" ON public.profiles
    FOR SELECT
    TO authenticated
    USING (public.is_admin());

CREATE POLICY "profiles_insert_self" ON public.profiles
    FOR INSERT
    TO authenticated
    WITH CHECK (
        auth.uid() = id
        AND COALESCE(is_admin, FALSE) = FALSE
        AND COALESCE(subscription_active, FALSE) = FALSE
        AND COALESCE(is_banned, FALSE) = FALSE
        AND subscription_expires_at IS NULL
        AND hwid IS NULL
    );

CREATE POLICY "profiles_update_self" ON public.profiles
    FOR UPDATE
    TO authenticated
    USING (auth.uid() = id)
    WITH CHECK (auth.uid() = id);

-- Trigger protecting all privileged profile fields even against direct client updates
CREATE OR REPLACE FUNCTION public.protect_profile_privileged_fields()
RETURNS TRIGGER AS $$
BEGIN
    IF (NEW.is_admin IS DISTINCT FROM OLD.is_admin) OR
       (NEW.subscription_active IS DISTINCT FROM OLD.subscription_active) OR
       (NEW.subscription_until IS DISTINCT FROM OLD.subscription_until) OR
       (NEW.subscription_expires_at IS DISTINCT FROM OLD.subscription_expires_at) OR
       (NEW.is_banned IS DISTINCT FROM OLD.is_banned) OR
       (NEW.hwid IS DISTINCT FROM OLD.hwid) OR
       (NEW.uid IS DISTINCT FROM OLD.uid) OR
       (NEW.email IS DISTINCT FROM OLD.email) THEN

        IF auth.role() = 'service_role' THEN
            RETURN NEW;
        END IF;

        IF current_setting('app.allow_profile_admin_update', true) = 'true' THEN
            RETURN NEW;
        END IF;

        RAISE EXCEPTION 'Access denied: cannot modify privileged profile columns' USING errcode = '42501';
    END IF;

    -- Validate mc_nickname length/characters if updated
    IF NEW.mc_nickname IS DISTINCT FROM OLD.mc_nickname THEN
        IF NEW.mc_nickname IS NULL OR LENGTH(TRIM(NEW.mc_nickname)) < 3 OR LENGTH(TRIM(NEW.mc_nickname)) > 16
           OR TRIM(NEW.mc_nickname) !~ '^[A-Za-z0-9_]{3,16}$' THEN
            RAISE EXCEPTION 'Invalid nickname format (3-16 alphanumeric/underscore)' USING errcode = '22023';
        END IF;
        NEW.mc_nickname := TRIM(NEW.mc_nickname);
    END IF;

    -- Restrict avatar_url to safe relative asset paths or https URLs without javascript/data
    IF NEW.avatar_url IS DISTINCT FROM OLD.avatar_url AND NEW.avatar_url IS NOT NULL THEN
        IF NEW.avatar_url !~ '^(/assets/[A-Za-z0-9_.-]+\.(png|jpg|jpeg|webp)|https://[A-Za-z0-9.-]+/.+)$'
           OR LENGTH(NEW.avatar_url) > 300 THEN
            RAISE EXCEPTION 'Invalid avatar URL' USING errcode = '22023';
        END IF;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, auth;

DROP TRIGGER IF EXISTS trg_protect_profile_fields ON public.profiles;
CREATE TRIGGER trg_protect_profile_fields
    BEFORE UPDATE ON public.profiles
    FOR EACH ROW EXECUTE FUNCTION public.protect_profile_privileged_fields();

-- ==============================================================================
-- 3. Site Config Table (Compatible with /ne, no sensitive data stored)
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.site_config (
    key TEXT PRIMARY KEY,
    value JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.site_config ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE r RECORD;
BEGIN
    FOR r IN (SELECT policyname FROM pg_policies WHERE tablename = 'site_config' AND schemaname = 'public') LOOP
        EXECUTE format('DROP POLICY IF EXISTS %I ON public.site_config;', r.policyname);
    END LOOP;
END $$;

CREATE POLICY "site_config_read_public" ON public.site_config
    FOR SELECT
    TO anon, authenticated
    USING (key = 'main');

-- Mutations only via service_role (Edge Function after TOTP 2FA verification)

INSERT INTO public.site_config (key, value)
VALUES (
    'main',
    jsonb_build_object(
        'brand_name', 'Shedness Launcher',
        'maintenance', false,
        'support_email', 'support@shedness.local'
    )
)
ON CONFLICT (key) DO NOTHING;

-- ==============================================================================
-- 4. License Keys Table (HMAC-signed + hashed storage, compatible with /ne)
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.license_keys (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    code TEXT,
    duration_days INT NOT NULL,
    is_used BOOLEAN NOT NULL DEFAULT FALSE,
    used_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.license_keys
    ALTER COLUMN code DROP NOT NULL;

ALTER TABLE public.license_keys
    ADD COLUMN IF NOT EXISTS key_hash TEXT,
    ADD COLUMN IF NOT EXISTS key_hmac TEXT,
    ADD COLUMN IF NOT EXISTS key_prefix TEXT,
    ADD COLUMN IF NOT EXISTS bound_user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS permissions JSONB NOT NULL DEFAULT '["launcher:download"]'::jsonb,
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS revoked_reason TEXT,
    ADD COLUMN IF NOT EXISTS created_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS used_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS used_by_user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_license_keys_key_hash_unique
    ON public.license_keys (key_hash)
    WHERE key_hash IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_license_keys_code_unique
    ON public.license_keys (UPPER(code))
    WHERE code IS NOT NULL;

ALTER TABLE public.license_keys ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE r RECORD;
BEGIN
    FOR r IN (SELECT policyname FROM pg_policies WHERE tablename = 'license_keys' AND schemaname = 'public') LOOP
        EXECUTE format('DROP POLICY IF EXISTS %I ON public.license_keys;', r.policyname);
    END LOOP;
END $$;

-- Regular users can only see keys bound directly to them (without exposing raw code/hmac)
-- Admins read keys via Edge Function (service_role) after TOTP 2FA verification.
CREATE POLICY "license_keys_select_bound_user" ON public.license_keys
    FOR SELECT
    TO authenticated
    USING (bound_user_id = auth.uid() OR used_by_user_id = auth.uid());

-- ==============================================================================
-- 5. Releases Table (Versioning, Platforms, SHA-256 Integrity)
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.releases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version TEXT NOT NULL,
    platform TEXT NOT NULL CHECK (platform IN ('windows', 'macos', 'linux')),
    channel TEXT NOT NULL DEFAULT 'stable' CHECK (channel IN ('stable', 'beta', 'alpha')),
    storage_path TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_size BIGINT NOT NULL CHECK (file_size > 0),
    sha256 TEXT NOT NULL CHECK (sha256 ~ '^[a-f0-9]{64}$'),
    changelog TEXT NOT NULL DEFAULT '',
    min_os TEXT NOT NULL DEFAULT 'Windows 10/11 x64',
    is_latest BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (version, platform)
);

ALTER TABLE public.releases ENABLE ROW LEVEL SECURITY;

-- Licensed active users and verified admins can read active release rows
DROP POLICY IF EXISTS "releases_select_licensed" ON public.releases;
CREATE POLICY "releases_select_licensed" ON public.releases
    FOR SELECT
    TO authenticated
    USING (
        is_active = TRUE
        AND (
            public.is_admin()
            OR EXISTS (
                SELECT 1 FROM public.profiles p
                WHERE p.id = auth.uid()
                  AND p.subscription_active = TRUE
                  AND COALESCE(p.is_banned, FALSE) = FALSE
                  AND (p.subscription_expires_at IS NULL OR p.subscription_expires_at > NOW())
            )
        )
    );

-- Public metadata RPC (omits storage_path completely!)
CREATE OR REPLACE FUNCTION public.get_public_releases()
RETURNS TABLE (
    id UUID,
    version TEXT,
    platform TEXT,
    channel TEXT,
    file_name TEXT,
    file_size BIGINT,
    sha256 TEXT,
    changelog TEXT,
    min_os TEXT,
    is_latest BOOLEAN,
    created_at TIMESTAMPTZ
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        r.id,
        r.version,
        r.platform,
        r.channel,
        r.file_name,
        r.file_size,
        r.sha256,
        r.changelog,
        r.min_os,
        r.is_latest,
        r.created_at
    FROM public.releases r
    WHERE r.is_active = TRUE
    ORDER BY r.is_latest DESC, r.created_at DESC
    LIMIT 25;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER STABLE SET search_path = public;

GRANT EXECUTE ON FUNCTION public.get_public_releases() TO anon, authenticated, service_role;

-- ==============================================================================
-- 6. Append-Only Audit Log Table
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.audit_log (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    actor_email TEXT,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    ip_address TEXT,
    user_agent TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON public.audit_log (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON public.audit_log (action);

ALTER TABLE public.audit_log ENABLE ROW LEVEL SECURITY;

-- Admins can read audit logs (no INSERT/UPDATE/DELETE policies for any client!)
DROP POLICY IF EXISTS "audit_log_select_admin" ON public.audit_log;
CREATE POLICY "audit_log_select_admin" ON public.audit_log
    FOR SELECT
    TO authenticated
    USING (public.is_admin());

-- Enforce strict append-only immutability at trigger level
CREATE OR REPLACE FUNCTION public.prevent_audit_log_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is strictly append-only' USING errcode = '42501';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_log_immutable ON public.audit_log;
CREATE TRIGGER trg_audit_log_immutable
    BEFORE UPDATE OR DELETE ON public.audit_log
    FOR EACH ROW EXECUTE FUNCTION public.prevent_audit_log_mutation();

-- ==============================================================================
-- 7. Admin TOTP 2FA & Short-Lived Admin Sessions (service_role ONLY)
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.admin_totp (
    user_id UUID PRIMARY KEY REFERENCES public.admins(user_id) ON DELETE CASCADE,
    secret_ciphertext TEXT NOT NULL,
    secret_iv TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.admin_totp ENABLE ROW LEVEL SECURITY;
-- Zero RLS policies: completely inaccessible to anon/authenticated; service_role only.

CREATE TABLE IF NOT EXISTS public.admin_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES public.admins(user_id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    ip_address TEXT,
    user_agent TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires ON public.admin_sessions (expires_at);

ALTER TABLE public.admin_sessions ENABLE ROW LEVEL SECURITY;
-- Zero RLS policies: service_role only.

-- ==============================================================================
-- 8. Rate Limits & Download Logs
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.rate_limits (
    bucket_key TEXT PRIMARY KEY,
    hit_count INT NOT NULL DEFAULT 1,
    window_start TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    blocked_until TIMESTAMPTZ
);

ALTER TABLE public.rate_limits ENABLE ROW LEVEL SECURITY;
-- Zero RLS policies: accessed strictly via consume_rate_limit() by service_role.

CREATE OR REPLACE FUNCTION public.consume_rate_limit(
    p_key TEXT,
    p_max INT,
    p_window_seconds INT,
    p_block_seconds INT DEFAULT 60
)
RETURNS JSONB AS $$
DECLARE
    v_now TIMESTAMPTZ := NOW();
    v_row public.rate_limits%ROWTYPE;
    v_new_count INT;
BEGIN
    IF p_key IS NULL OR LENGTH(p_key) = 0 THEN
        RETURN jsonb_build_object('allowed', FALSE, 'remaining', 0, 'retry_after', p_block_seconds);
    END IF;

    INSERT INTO public.rate_limits (bucket_key, hit_count, window_start, blocked_until)
    VALUES (p_key, 1, v_now, NULL)
    ON CONFLICT (bucket_key) DO NOTHING;

    SELECT * INTO v_row FROM public.rate_limits WHERE bucket_key = p_key FOR UPDATE;

    IF v_row.blocked_until IS NOT NULL AND v_row.blocked_until > v_now THEN
        RETURN jsonb_build_object(
            'allowed', FALSE,
            'remaining', 0,
            'retry_after', GREATEST(1, CEIL(EXTRACT(EPOCH FROM (v_row.blocked_until - v_now)))::INT)
        );
    END IF;

    IF v_row.window_start + (p_window_seconds || ' seconds')::INTERVAL <= v_now THEN
        UPDATE public.rate_limits
        SET hit_count = 1, window_start = v_now, blocked_until = NULL
        WHERE bucket_key = p_key;

        RETURN jsonb_build_object('allowed', TRUE, 'remaining', GREATEST(0, p_max - 1), 'retry_after', 0);
    END IF;

    v_new_count := v_row.hit_count + 1;

    IF v_new_count > p_max THEN
        UPDATE public.rate_limits
        SET hit_count = v_new_count,
            blocked_until = v_now + (p_block_seconds || ' seconds')::INTERVAL
        WHERE bucket_key = p_key;

        RETURN jsonb_build_object('allowed', FALSE, 'remaining', 0, 'retry_after', p_block_seconds);
    END IF;

    UPDATE public.rate_limits
    SET hit_count = v_new_count
    WHERE bucket_key = p_key;

    RETURN jsonb_build_object('allowed', TRUE, 'remaining', GREATEST(0, p_max - v_new_count), 'retry_after', 0);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

REVOKE ALL ON FUNCTION public.consume_rate_limit(TEXT, INT, INT, INT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.consume_rate_limit(TEXT, INT, INT, INT) FROM anon;
REVOKE ALL ON FUNCTION public.consume_rate_limit(TEXT, INT, INT, INT) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.consume_rate_limit(TEXT, INT, INT, INT) TO service_role;

CREATE TABLE IF NOT EXISTS public.download_logs (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    release_id UUID NOT NULL REFERENCES public.releases(id) ON DELETE CASCADE,
    ip_address TEXT,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.download_logs ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "download_logs_select_self" ON public.download_logs;
CREATE POLICY "download_logs_select_self" ON public.download_logs
    FOR SELECT
    TO authenticated
    USING (auth.uid() = user_id);

-- ==============================================================================
-- 9. Lock Down Legacy RPCs (Force Admin & Key Redemption Through Edge Functions)
-- ==============================================================================
DO $$
DECLARE
    fn_sig TEXT;
BEGIN
    FOREACH fn_sig IN ARRAY ARRAY[
        'public.admin_ban_user(UUID)',
        'public.admin_unban_user(UUID)',
        'public.admin_grant_subscription(UUID, INT)',
        'public.admin_revoke_subscription(UUID)',
        'public.admin_reset_hwid(UUID)',
        'public.admin_toggle_role(UUID, BOOLEAN)',
        'public.admin_toggle_maintenance()',
        'public.admin_load_users()',
        'public.admin_create_key(INT)',
        'public.is_master_admin()',
        'public.redeem_license_key(TEXT)',
        'public.reset_hwid_with_key(TEXT)',
        'public.check_license_key(TEXT)',
        'public.get_email_by_nickname(TEXT)'
    ] LOOP
        IF to_regprocedure(fn_sig) IS NOT NULL THEN
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC;', fn_sig);
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM anon;', fn_sig);
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM authenticated;', fn_sig);
            EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO service_role;', fn_sig);
        END IF;
    END LOOP;
END $$;

-- Atomic key redemption RPC called ONLY by Edge Function (service_role)
CREATE OR REPLACE FUNCTION public.srv_redeem_license_key(
    p_user_id UUID,
    p_key_id BIGINT
)
RETURNS JSONB AS $$
DECLARE
    v_key public.license_keys%ROWTYPE;
    v_prof public.profiles%ROWTYPE;
    v_sub_text TEXT;
    v_exp_ts TIMESTAMPTZ;
    v_base_ts TIMESTAMPTZ;
BEGIN
    SELECT * INTO v_key FROM public.license_keys WHERE id = p_key_id FOR UPDATE;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('ok', FALSE, 'error', 'key_not_found');
    END IF;

    IF v_key.revoked_at IS NOT NULL THEN
        RETURN jsonb_build_object('ok', FALSE, 'error', 'key_revoked');
    END IF;

    IF v_key.is_used THEN
        RETURN jsonb_build_object('ok', FALSE, 'error', 'key_already_used');
    END IF;

    IF v_key.expires_at IS NOT NULL AND v_key.expires_at < NOW() THEN
        RETURN jsonb_build_object('ok', FALSE, 'error', 'key_expired');
    END IF;

    IF v_key.bound_user_id IS NOT NULL AND v_key.bound_user_id <> p_user_id THEN
        RETURN jsonb_build_object('ok', FALSE, 'error', 'key_bound_to_another_user');
    END IF;

    SELECT * INTO v_prof FROM public.profiles WHERE id = p_user_id FOR UPDATE;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('ok', FALSE, 'error', 'profile_not_found');
    END IF;

    IF COALESCE(v_prof.is_banned, FALSE) THEN
        RETURN jsonb_build_object('ok', FALSE, 'error', 'account_banned');
    END IF;

    PERFORM set_config('app.allow_profile_admin_update', 'true', true);

    -- HWID Reset key
    IF v_key.duration_days = 0 THEN
        UPDATE public.license_keys
        SET is_used = TRUE,
            used_at = NOW(),
            used_by_user_id = p_user_id,
            used_by = COALESCE(v_prof.mc_nickname, p_user_id::TEXT)
        WHERE id = v_key.id;

        UPDATE public.profiles
        SET hwid = NULL
        WHERE id = p_user_id;

        RETURN jsonb_build_object('ok', TRUE, 'type', 'reset', 'until', COALESCE(v_prof.subscription_until, 'Не активна'));
    END IF;

    -- Subscription key (extends existing unexpired subscription if applicable)
    IF v_key.duration_days < 0 OR v_key.duration_days >= 9000 THEN
        v_sub_text := 'Навсегда (Lifetime)';
        v_exp_ts := NULL;
    ELSE
        v_base_ts := GREATEST(NOW(), COALESCE(v_prof.subscription_expires_at, NOW()));
        v_exp_ts := v_base_ts + (v_key.duration_days || ' days')::INTERVAL;
        v_sub_text := 'до ' || to_char(v_exp_ts::DATE, 'DD.MM.YYYY');
    END IF;

    UPDATE public.license_keys
    SET is_used = TRUE,
        used_at = NOW(),
        used_by_user_id = p_user_id,
        used_by = COALESCE(v_prof.mc_nickname, p_user_id::TEXT)
    WHERE id = v_key.id;

    UPDATE public.profiles
    SET subscription_active = TRUE,
        subscription_until = v_sub_text,
        subscription_expires_at = v_exp_ts
    WHERE id = p_user_id;

    RETURN jsonb_build_object(
        'ok', TRUE,
        'type', 'subscription',
        'until', v_sub_text,
        'expires_at', v_exp_ts
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

REVOKE ALL ON FUNCTION public.srv_redeem_license_key(UUID, BIGINT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.srv_redeem_license_key(UUID, BIGINT) FROM anon;
REVOKE ALL ON FUNCTION public.srv_redeem_license_key(UUID, BIGINT) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.srv_redeem_license_key(UUID, BIGINT) TO service_role;

-- ==============================================================================
-- 10. Private Storage Bucket for Launcher Binaries (Strict Deny-All Client RLS)
-- ==============================================================================
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES (
    'launcher-releases',
    'launcher-releases',
    FALSE,
    524288000,
    ARRAY[
        'application/octet-stream',
        'application/x-msdownload',
        'application/x-dosexec',
        'application/vnd.microsoft.portable-executable',
        'application/zip',
        'application/x-apple-diskimage',
        'application/x-tar',
        'application/gzip'
    ]
)
ON CONFLICT (id) DO UPDATE
SET public = FALSE,
    file_size_limit = EXCLUDED.file_size_limit,
    allowed_mime_types = EXCLUDED.allowed_mime_types;

-- Ensure no public/authenticated policy permits direct listing/reading of launcher-releases
DO $$
DECLARE r RECORD;
BEGIN
    FOR r IN (
        SELECT policyname FROM pg_policies
        WHERE schemaname = 'storage' AND tablename = 'objects'
          AND policyname ILIKE '%launcher%'
    ) LOOP
        EXECUTE format('DROP POLICY IF EXISTS %I ON storage.objects;', r.policyname);
    END LOOP;
END $$;

-- ==============================================================================
-- 11. Auto-Create Profile Trigger & Launcher HWID Binding (Fresh + /ne compatible)
-- ==============================================================================
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
DECLARE
    v_max_uid BIGINT;
    v_nick TEXT;
BEGIN
    SELECT COALESCE(MAX(uid), 0) + 1 INTO v_max_uid FROM public.profiles;
    v_nick := COALESCE(
        NULLIF(TRIM(NEW.raw_user_meta_data->>'mc_nickname'), ''),
        SPLIT_PART(NEW.email, '@', 1)
    );

    INSERT INTO public.profiles (
        id,
        email,
        mc_nickname,
        hwid,
        subscription_active,
        subscription_until,
        is_admin,
        uid,
        created_at
    )
    VALUES (
        NEW.id,
        NEW.email,
        LEFT(REGEXP_REPLACE(v_nick, '[^A-Za-z0-9_]', '_', 'g'), 16),
        NULL,
        FALSE,
        'Не активна',
        FALSE,
        v_max_uid,
        NOW()
    )
    ON CONFLICT (id) DO UPDATE SET
        email = EXCLUDED.email,
        mc_nickname = COALESCE(public.profiles.mc_nickname, EXCLUDED.mc_nickname);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

CREATE OR REPLACE FUNCTION public.bind_hwid(p_hwid TEXT)
RETURNS JSONB AS $$
DECLARE
    v_uid UUID := auth.uid();
    v_current TEXT;
    v_clean TEXT;
BEGIN
    IF v_uid IS NULL THEN
        RETURN jsonb_build_object('ok', FALSE, 'error', 'not_authenticated');
    END IF;

    v_clean := TRIM(COALESCE(p_hwid, ''));
    IF v_clean = '' OR v_clean = 'null' OR LENGTH(v_clean) > 128 THEN
        RETURN jsonb_build_object('ok', FALSE, 'error', 'invalid_hwid');
    END IF;

    SELECT hwid INTO v_current FROM public.profiles WHERE id = v_uid;

    IF v_current IS NOT NULL AND TRIM(v_current) != '' AND v_current != 'null' THEN
        IF v_current = v_clean THEN
            RETURN jsonb_build_object('ok', TRUE, 'message', 'already_bound');
        ELSE
            RETURN jsonb_build_object('ok', FALSE, 'error', 'hwid_mismatch');
        END IF;
    END IF;

    PERFORM set_config('app.allow_profile_admin_update', 'true', true);
    UPDATE public.profiles SET hwid = v_clean WHERE id = v_uid;

    RETURN jsonb_build_object('ok', TRUE, 'message', 'hwid_bound');
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

REVOKE ALL ON FUNCTION public.bind_hwid(TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.bind_hwid(TEXT) FROM anon;
GRANT EXECUTE ON FUNCTION public.bind_hwid(TEXT) TO authenticated, service_role;

-- Backfill profiles for users registered before this migration
DO $$
DECLARE
    u RECORD;
    v_next_uid BIGINT;
BEGIN
    SELECT COALESCE(MAX(uid), 0) INTO v_next_uid FROM public.profiles;
    FOR u IN (
        SELECT au.id, au.email, au.raw_user_meta_data
        FROM auth.users au
        LEFT JOIN public.profiles p ON p.id = au.id
        WHERE p.id IS NULL
        ORDER BY au.created_at ASC
    ) LOOP
        v_next_uid := v_next_uid + 1;
        INSERT INTO public.profiles (
            id, email, mc_nickname, hwid, subscription_active, subscription_until, is_admin, uid, created_at
        )
        VALUES (
            u.id,
            u.email,
            LEFT(REGEXP_REPLACE(COALESCE(NULLIF(TRIM(u.raw_user_meta_data->>'mc_nickname'), ''), SPLIT_PART(u.email, '@', 1)), '[^A-Za-z0-9_]', '_', 'g'), 16),
            NULL,
            FALSE,
            'Не активна',
            FALSE,
            v_next_uid,
            NOW()
        )
        ON CONFLICT (id) DO NOTHING;
    END LOOP;
END $$;

-- Safe RPC for authenticated client to ensure own profile row exists
CREATE OR REPLACE FUNCTION public.ensure_my_profile()
RETURNS VOID AS $$
DECLARE
    v_uid UUID := auth.uid();
    v_email TEXT;
    v_meta JSONB;
    v_next_uid BIGINT;
BEGIN
    IF v_uid IS NULL THEN
        RETURN;
    END IF;
    IF EXISTS (SELECT 1 FROM public.profiles WHERE id = v_uid) THEN
        RETURN;
    END IF;

    SELECT email, raw_user_meta_data INTO v_email, v_meta FROM auth.users WHERE id = v_uid;
    IF v_email IS NULL THEN
        RETURN;
    END IF;

    SELECT COALESCE(MAX(uid), 0) + 1 INTO v_next_uid FROM public.profiles;
    INSERT INTO public.profiles (
        id, email, mc_nickname, hwid, subscription_active, subscription_until, is_admin, uid, created_at
    )
    VALUES (
        v_uid,
        v_email,
        LEFT(REGEXP_REPLACE(COALESCE(NULLIF(TRIM(v_meta->>'mc_nickname'), ''), SPLIT_PART(v_email, '@', 1)), '[^A-Za-z0-9_]', '_', 'g'), 16),
        NULL,
        FALSE,
        'Не активна',
        FALSE,
        v_next_uid,
        NOW()
    )
    ON CONFLICT (id) DO NOTHING;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, auth;

REVOKE ALL ON FUNCTION public.ensure_my_profile() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ensure_my_profile() FROM anon;
GRANT EXECUTE ON FUNCTION public.ensure_my_profile() TO authenticated, service_role;

-- ==============================================================================
-- 12. Explicit Least-Privilege Table GRANTs (Required when default grants are restricted)
-- ==============================================================================
GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC, anon, authenticated;

-- Service role keeps full backend access
GRANT ALL ON ALL TABLES IN SCHEMA public TO service_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO service_role;

-- Public & authenticated minimal table grants (row access still strictly enforced by RLS)
GRANT SELECT ON public.site_config TO anon, authenticated;
GRANT SELECT, INSERT, UPDATE ON public.profiles TO authenticated;
GRANT SELECT ON public.admins TO authenticated;
GRANT SELECT ON public.license_keys TO authenticated;
GRANT SELECT ON public.releases TO authenticated;
GRANT SELECT ON public.audit_log TO authenticated;
GRANT SELECT ON public.download_logs TO authenticated;
-- Zero grants on admin_totp, admin_sessions, rate_limits for anon/authenticated

CREATE TABLE IF NOT EXISTS vorken_customers (
 id UUID PRIMARY KEY, discord_id TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
 email TEXT, status TEXT NOT NULL DEFAULT 'active', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS vorken_logins (
 token_hash TEXT PRIMARY KEY, customer_id UUID NOT NULL REFERENCES vorken_customers(id),
 access_token TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS vorken_plans (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, months INTEGER NOT NULL CHECK (months IN (1,3,6,12)),
 price_cents INTEGER CHECK (price_cents > 0), max_servers INTEGER NOT NULL DEFAULT 1 CHECK (max_servers BETWEEN 1 AND 100), enabled BOOLEAN NOT NULL DEFAULT TRUE
);
INSERT INTO vorken_plans(id,name,months) VALUES
 ('mensal','Mensal',1),('trimestral','Trimestral',3),('semestral','Semestral',6),('anual','Anual',12)
ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS vorken_licenses (
 customer_id UUID PRIMARY KEY REFERENCES vorken_customers(id), plan_id TEXT REFERENCES vorken_plans(id),
 status TEXT NOT NULL DEFAULT 'inactive', expires_at TIMESTAMPTZ, max_servers INTEGER NOT NULL DEFAULT 1 CHECK (max_servers BETWEEN 1 AND 100)
);
CREATE TABLE IF NOT EXISTS vorken_guilds (
 id TEXT PRIMARY KEY, customer_id UUID NOT NULL REFERENCES vorken_customers(id), name TEXT NOT NULL,
 verification_channel_id TEXT, alerts_channel_id TEXT, category_id TEXT, verified_role_id TEXT, screening_role_id TEXT
);
CREATE TABLE IF NOT EXISTS vorken_servers (
 id UUID PRIMARY KEY, customer_id UUID NOT NULL REFERENCES vorken_customers(id), guild_id TEXT NOT NULL REFERENCES vorken_guilds(id),
 name TEXT NOT NULL, discord_invite TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
 enabled BOOLEAN NOT NULL DEFAULT TRUE, last_seen TIMESTAMPTZ, plugin_version TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS vorken_sessions (
 id UUID PRIMARY KEY, server_id UUID NOT NULL REFERENCES vorken_servers(id), steam_id TEXT NOT NULL, player_name TEXT NOT NULL,
 code TEXT NOT NULL, administrator_id TEXT, discord_user_id TEXT, ticket_channel_id TEXT,
 analysis_id BIGINT UNIQUE REFERENCES analyses(id), status TEXT NOT NULL DEFAULT 'pending',
 expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE vorken_servers ADD COLUMN IF NOT EXISTS online_players JSONB NOT NULL DEFAULT '[]';
ALTER TABLE vorken_servers ADD COLUMN IF NOT EXISTS players_updated_at TIMESTAMPTZ;
CREATE UNIQUE INDEX IF NOT EXISTS vorken_active_code ON vorken_sessions(server_id,code) WHERE status IN ('pending','redeemed','deciding');
CREATE TABLE IF NOT EXISTS vorken_commands (
 id UUID PRIMARY KEY, server_id UUID NOT NULL REFERENCES vorken_servers(id), session_id UUID REFERENCES vorken_sessions(id),
 action TEXT NOT NULL CHECK(action IN ('start','attend','approve','deny')), steam_id TEXT NOT NULL, actor_id TEXT,
 reason TEXT NOT NULL DEFAULT '', evidence_ids JSONB NOT NULL DEFAULT '[]', trusted_ids JSONB NOT NULL DEFAULT '[]',
 status TEXT NOT NULL DEFAULT 'pending', result TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), completed_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS vorken_one_decision ON vorken_commands(session_id) WHERE action IN ('approve','deny') AND status IN ('pending','applied');
CREATE TABLE IF NOT EXISTS vorken_events (
 id UUID PRIMARY KEY, server_id UUID NOT NULL REFERENCES vorken_servers(id), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS vorken_bans (
 id UUID PRIMARY KEY, session_id UUID UNIQUE REFERENCES vorken_sessions(id), server_id UUID NOT NULL REFERENCES vorken_servers(id),
 steam_id TEXT NOT NULL, reason TEXT NOT NULL, evidence JSONB NOT NULL, active BOOLEAN NOT NULL DEFAULT TRUE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS vorken_ban_player ON vorken_bans(steam_id) WHERE active;
CREATE TABLE IF NOT EXISTS vorken_notices (
 id UUID PRIMARY KEY, guild_id TEXT NOT NULL REFERENCES vorken_guilds(id), kind TEXT NOT NULL, payload JSONB NOT NULL,
 sent_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS vorken_orders (
 id UUID PRIMARY KEY, customer_id UUID NOT NULL REFERENCES vorken_customers(id), plan_id TEXT NOT NULL REFERENCES vorken_plans(id),
 price_cents INTEGER NOT NULL, months INTEGER NOT NULL, max_servers INTEGER NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending', provider TEXT, provider_id TEXT, checkout_url TEXT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), paid_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS vorken_audit (
 id BIGSERIAL PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL,
 details JSONB NOT NULL DEFAULT '{}', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE vorken_servers ADD COLUMN IF NOT EXISTS slug TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS vorken_server_slug ON vorken_servers(slug);
ALTER TABLE vorken_sessions ADD COLUMN IF NOT EXISTS notified_stage TEXT;
ALTER TABLE vorken_commands ADD COLUMN IF NOT EXISTS learning_complete BOOLEAN NOT NULL DEFAULT FALSE;

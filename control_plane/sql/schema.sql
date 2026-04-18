create extension if not exists "uuid-ossp";

create table if not exists tenants (
    id uuid primary key default uuid_generate_v4(),
    name varchar(255) not null unique,
    plan varchar(32) not null,
    created_at timestamptz not null default now(),
    status varchar(32) not null,
    namespace varchar(128) not null default 'sentinelai-default',
    kafka_topic_prefix varchar(128) not null default 'tenant',
    agent_limit integer not null default 10,
    eps_limit integer not null default 25,
    storage_limit_mb integer not null default 1024,
    retention_days integer not null default 30
);

create table if not exists users (
    id uuid primary key default uuid_generate_v4(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    email varchar(255) not null,
    password_hash varchar(255) not null,
    role varchar(32) not null,
    is_active boolean not null default true,
    created_at timestamptz not null default now()
);
create index if not exists idx_users_tenant_id on users(tenant_id);
create unique index if not exists idx_users_tenant_email on users(tenant_id, email);

create table if not exists agents (
    id uuid primary key default uuid_generate_v4(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    hostname varchar(255) not null,
    os varchar(64) not null,
    status varchar(32) not null,
    last_heartbeat timestamptz,
    agent_version varchar(64) not null,
    machine_id varchar(255),
    enrollment_token varchar(255),
    kafka_username varchar(255),
    kafka_password varchar(255),
    created_at timestamptz not null default now()
);
create index if not exists idx_agents_tenant_id on agents(tenant_id);

create table if not exists incidents (
    id uuid primary key default uuid_generate_v4(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    severity varchar(32) not null,
    ml_score double precision not null default 0.0,
    status varchar(32) not null,
    created_at timestamptz not null default now(),
    title varchar(255) not null default 'SentinelAI Incident',
    description text not null default '',
    metadata jsonb not null default '{}'::jsonb
);
create index if not exists idx_incidents_tenant_created on incidents(tenant_id, created_at desc);

create table if not exists usage_metrics (
    id bigserial primary key,
    tenant_id uuid not null references tenants(id) on delete cascade,
    timestamp timestamptz not null default now(),
    events_ingested integer not null default 0,
    api_calls integer not null default 0,
    ml_inference_count integer not null default 0,
    storage_mb double precision not null default 0.0
);
create index if not exists idx_usage_metrics_tenant_time on usage_metrics(tenant_id, timestamp desc);

create table if not exists policies (
    id uuid primary key default uuid_generate_v4(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    name varchar(255) not null,
    description text not null default '',
    enabled boolean not null default true,
    conditions jsonb not null default '{}'::jsonb,
    actions jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now()
);
create index if not exists idx_policies_tenant_id on policies(tenant_id);

create table if not exists refresh_tokens (
    id uuid primary key default uuid_generate_v4(),
    user_id uuid not null references users(id) on delete cascade,
    tenant_id uuid not null references tenants(id) on delete cascade,
    token_hash varchar(255) not null,
    expires_at timestamptz not null,
    revoked boolean not null default false,
    created_at timestamptz not null default now()
);

create table if not exists audit_logs (
    id uuid primary key default uuid_generate_v4(),
    tenant_id uuid not null,
    actor_user_id uuid,
    action varchar(255) not null,
    target_resource varchar(255) not null,
    timestamp timestamptz not null default now(),
    metadata jsonb not null default '{}'::jsonb
);
create index if not exists idx_audit_logs_tenant_time on audit_logs(tenant_id, timestamp desc);

create table if not exists subscriptions (
    id uuid primary key default uuid_generate_v4(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    plan varchar(32) not null,
    status varchar(32) not null default 'active',
    billing_cycle varchar(32) not null default 'monthly',
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);
create index if not exists idx_subscriptions_tenant_id on subscriptions(tenant_id);

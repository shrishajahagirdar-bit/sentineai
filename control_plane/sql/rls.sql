alter table users enable row level security;
alter table agents enable row level security;
alter table incidents enable row level security;
alter table usage_metrics enable row level security;
alter table policies enable row level security;
alter table refresh_tokens enable row level security;
alter table audit_logs enable row level security;
alter table subscriptions enable row level security;

drop policy if exists users_tenant_isolation on users;
create policy users_tenant_isolation on users
using (tenant_id::text = current_setting('app.current_tenant_id', true));

drop policy if exists agents_tenant_isolation on agents;
create policy agents_tenant_isolation on agents
using (tenant_id::text = current_setting('app.current_tenant_id', true));

drop policy if exists incidents_tenant_isolation on incidents;
create policy incidents_tenant_isolation on incidents
using (tenant_id::text = current_setting('app.current_tenant_id', true));

drop policy if exists usage_metrics_tenant_isolation on usage_metrics;
create policy usage_metrics_tenant_isolation on usage_metrics
using (tenant_id::text = current_setting('app.current_tenant_id', true));

drop policy if exists policies_tenant_isolation on policies;
create policy policies_tenant_isolation on policies
using (tenant_id::text = current_setting('app.current_tenant_id', true));

drop policy if exists refresh_tokens_tenant_isolation on refresh_tokens;
create policy refresh_tokens_tenant_isolation on refresh_tokens
using (tenant_id::text = current_setting('app.current_tenant_id', true));

drop policy if exists audit_logs_tenant_isolation on audit_logs;
create policy audit_logs_tenant_isolation on audit_logs
using (tenant_id::text = current_setting('app.current_tenant_id', true));

drop policy if exists subscriptions_tenant_isolation on subscriptions;
create policy subscriptions_tenant_isolation on subscriptions
using (tenant_id::text = current_setting('app.current_tenant_id', true));

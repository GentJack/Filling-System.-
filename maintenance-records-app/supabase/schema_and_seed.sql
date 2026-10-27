-- =====================================================================
-- Maintenance Records: Supabase (Postgres) schema + simple test data
-- Paste into Supabase > SQL Editor > Run. Safe to re-run (drops first).
-- =====================================================================

drop table if exists notifications, devices, share_links, activity_log, access_requests,
  signatures, document_revisions, documents, folder_access, folders,
  work_orders, aircraft, profiles cascade;
drop type if exists app_role, access_level, doc_status, activity_result cascade;

create type app_role       as enum ('admin','engineer','technician','planner','auditor');
create type access_level   as enum ('view','upload','sign','manage');
create type doc_status     as enum ('draft','awaiting_signature','signed','superseded');
create type activity_result as enum ('ok','denied','failed');

-- ---------- People ---------------------------------------------------
-- Rows can exist before the person signs up. When someone signs up with
-- the same email, auth_user_id is linked automatically (trigger below).
create table profiles (
  id           uuid primary key default gen_random_uuid(),
  auth_user_id uuid unique references auth.users(id) on delete set null,
  email        text not null unique,
  full_name    text not null,
  role         app_role not null default 'technician',
  active       boolean not null default true,
  created_at   timestamptz not null default now()
);

-- ---------- Aircraft and work ----------------------------------------
create table aircraft (
  id           uuid primary key default gen_random_uuid(),
  registration text not null unique,       -- e.g. ZS-XXX
  type         text not null
);

create table work_orders (
  id           uuid primary key default gen_random_uuid(),
  aircraft_id  uuid not null references aircraft(id) on delete cascade,
  number       text not null unique,
  title        text not null,
  status       text not null default 'open'
);

-- ---------- Folders and access ---------------------------------------
create table folders (
  id          uuid primary key default gen_random_uuid(),
  name        text not null unique,
  owner_id    uuid references profiles(id),
  created_at  timestamptz not null default now()
);

create table folder_access (
  folder_id   uuid not null references folders(id) on delete cascade,
  profile_id  uuid not null references profiles(id) on delete cascade,
  level       access_level not null default 'view',
  primary key (folder_id, profile_id)
);

-- ---------- Documents ------------------------------------------------
create table documents (
  id             uuid primary key default gen_random_uuid(),
  folder_id      uuid not null references folders(id) on delete cascade,
  aircraft_id    uuid references aircraft(id),
  work_order_id  uuid references work_orders(id),
  title          text not null,
  status         doc_status not null default 'draft',
  current_rev    int not null default 1,
  created_by     uuid references profiles(id),
  created_at     timestamptz not null default now()
);

create table document_revisions (
  id           uuid primary key default gen_random_uuid(),
  document_id  uuid not null references documents(id) on delete cascade,
  revision     int  not null,
  file_path    text,                        -- path in Supabase Storage bucket 'records'
  note         text,
  uploaded_by  uuid references profiles(id),
  uploaded_at  timestamptz not null default now(),
  unique (document_id, revision)
);

create table signatures (
  id           uuid primary key default gen_random_uuid(),
  document_id  uuid not null references documents(id) on delete cascade,
  revision     int  not null,
  signed_by    uuid not null references profiles(id),
  signed_at    timestamptz not null default now(),
  unique (document_id, revision, signed_by)
);

-- ---------- Requests, sharing, activity ------------------------------
create table access_requests (
  id          uuid primary key default gen_random_uuid(),
  folder_id   uuid not null references folders(id) on delete cascade,
  profile_id  uuid not null references profiles(id) on delete cascade,
  reason      text,
  status      text not null default 'pending' check (status in ('pending','approved','declined')),
  created_at  timestamptz not null default now()
);

create table share_links (
  id           uuid primary key default gen_random_uuid(),
  document_id  uuid not null references documents(id) on delete cascade,
  token        text not null unique default encode(gen_random_bytes(16),'hex'),
  expires_at   timestamptz not null default now() + interval '7 days',
  created_by   uuid references profiles(id)
);

create table activity_log (
  id          bigint generated always as identity primary key,
  at          timestamptz not null default now(),
  profile_id  uuid references profiles(id),
  action      text not null,               -- Viewed, Signed, Downloaded, Tried to open ...
  target      text,
  device      text,
  result      activity_result not null default 'ok'
);

create table notifications (
  id          uuid primary key default gen_random_uuid(),
  profile_id  uuid not null references profiles(id) on delete cascade,
  message     text not null,
  read        boolean not null default false,
  created_at  timestamptz not null default now()
);

create table devices (
  id          uuid primary key default gen_random_uuid(),
  profile_id  uuid not null references profiles(id) on delete cascade,
  name        text not null,
  last_seen   timestamptz not null default now()
);

create index on documents (folder_id);
create index on activity_log (at desc);
create index on notifications (profile_id, read);

-- ---------- Link a signup to its profile by email --------------------
create or replace function link_profile_on_signup() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  update profiles set auth_user_id = new.id where lower(email) = lower(new.email);
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function link_profile_on_signup();

-- ---------- Row Level Security helpers -------------------------------
create or replace function me() returns uuid
language sql stable security definer set search_path = public as
$$ select id from profiles where auth_user_id = auth.uid() and active $$;

create or replace function is_admin() returns boolean
language sql stable security definer set search_path = public as
$$ select exists (select 1 from profiles where auth_user_id = auth.uid() and active and role = 'admin') $$;

create or replace function can_see_folder(f uuid) returns boolean
language sql stable security definer set search_path = public as
$$ select is_admin() or exists (select 1 from folder_access where folder_id = f and profile_id = me()) $$;

create or replace function can_sign_in_folder(f uuid) returns boolean
language sql stable security definer set search_path = public as
$$ select exists (select 1 from folder_access where folder_id = f and profile_id = me() and level in ('sign','manage')) $$;

alter table profiles           enable row level security;
alter table aircraft           enable row level security;
alter table work_orders        enable row level security;
alter table folders            enable row level security;
alter table folder_access      enable row level security;
alter table documents          enable row level security;
alter table document_revisions enable row level security;
alter table signatures         enable row level security;
alter table access_requests    enable row level security;
alter table share_links        enable row level security;
alter table activity_log       enable row level security;
alter table notifications      enable row level security;
alter table devices            enable row level security;

-- Everyone signed in can see people, aircraft and work orders; only admins change people.
create policy "read profiles"   on profiles    for select to authenticated using (true);
create policy "admin profiles"  on profiles    for all    to authenticated using (is_admin()) with check (is_admin());
create policy "read aircraft"   on aircraft    for select to authenticated using (true);
create policy "read work orders" on work_orders for select to authenticated using (true);

-- Folders: only the ones you have access to (admins see all).
create policy "read folders"  on folders for select to authenticated using (can_see_folder(id));
create policy "admin folders" on folders for all    to authenticated using (is_admin()) with check (is_admin());
create policy "read own access" on folder_access for select to authenticated using (profile_id = me() or is_admin());
create policy "admin access"    on folder_access for all    to authenticated using (is_admin()) with check (is_admin());

-- Documents follow folder access.
create policy "read documents" on documents for select to authenticated using (can_see_folder(folder_id));
create policy "add documents"  on documents for insert to authenticated with check (
  is_admin() or exists (select 1 from folder_access where folder_id = documents.folder_id
                        and profile_id = me() and level in ('upload','sign','manage')));
create policy "read revisions" on document_revisions for select to authenticated using (
  exists (select 1 from documents d where d.id = document_id and can_see_folder(d.folder_id)));
create policy "add revisions"  on document_revisions for insert to authenticated with check (
  exists (select 1 from documents d where d.id = document_id and can_see_folder(d.folder_id)));
create policy "read signatures" on signatures for select to authenticated using (
  exists (select 1 from documents d where d.id = document_id and can_see_folder(d.folder_id)));
create policy "sign" on signatures for insert to authenticated with check (
  signed_by = me() and exists (select 1 from documents d where d.id = document_id and can_sign_in_folder(d.folder_id)));

-- Requests, notifications, devices: your own (admins see requests).
create policy "own requests"  on access_requests for select to authenticated using (profile_id = me() or is_admin());
create policy "make request"  on access_requests for insert to authenticated with check (profile_id = me());
create policy "admin decide"  on access_requests for update to authenticated using (is_admin());
create policy "own notifications" on notifications for all to authenticated using (profile_id = me()) with check (profile_id = me());
create policy "own devices"       on devices       for all to authenticated using (profile_id = me()) with check (profile_id = me());
create policy "own share links"   on share_links   for all to authenticated using (created_by = me() or is_admin()) with check (created_by = me());

-- Activity log is append-only: anyone can add their own entries, admins/auditors read all.
create policy "log own"  on activity_log for insert to authenticated with check (profile_id = me());
create policy "read log" on activity_log for select to authenticated using (
  profile_id = me() or is_admin() or exists (select 1 from profiles where id = me() and role = 'auditor'));
-- no update or delete policies, so entries can't be edited or deleted.

-- =====================================================================
-- SIMPLE TEST DATA (fixed ids so rows can reference each other)
-- =====================================================================
insert into profiles (id, email, full_name, role) values
 ('00000000-0000-0000-0000-000000000001','admin@example.com',     'Test Admin',      'admin'),
 ('00000000-0000-0000-0000-000000000002','engineer@example.com',  'Test Engineer',   'engineer'),
 ('00000000-0000-0000-0000-000000000003','technician@example.com','Test Technician', 'technician'),
 ('00000000-0000-0000-0000-000000000004','planner@example.com',   'Test Planner',    'planner'),
 ('00000000-0000-0000-0000-000000000005','auditor@example.com',   'Test Auditor',    'auditor');

insert into aircraft (id, registration, type) values
 ('10000000-0000-0000-0000-000000000001','ZS-XXX','Boeing 737-800'),
 ('10000000-0000-0000-0000-000000000002','ZS-YYY','Airbus A320');

insert into work_orders (id, aircraft_id, number, title) values
 ('20000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000001','WO-2041','A-check'),
 ('20000000-0000-0000-0000-000000000002','10000000-0000-0000-0000-000000000002','WO-2042','Landing gear inspection');

insert into folders (id, name, owner_id) values
 ('30000000-0000-0000-0000-000000000001','Task cards',     '00000000-0000-0000-0000-000000000002'),
 ('30000000-0000-0000-0000-000000000002','Manuals',        '00000000-0000-0000-0000-000000000001'),
 ('30000000-0000-0000-0000-000000000003','Technical logs', '00000000-0000-0000-0000-000000000002'),
 ('30000000-0000-0000-0000-000000000004','Releases (CRS)', '00000000-0000-0000-0000-000000000001');

-- Technician has no access to Releases (CRS), matching the "No access" screen.
insert into folder_access (folder_id, profile_id, level) values
 ('30000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002','sign'),
 ('30000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000002','view'),
 ('30000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000002','sign'),
 ('30000000-0000-0000-0000-000000000004','00000000-0000-0000-0000-000000000002','sign'),
 ('30000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000003','upload'),
 ('30000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000003','view'),
 ('30000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000003','upload'),
 ('30000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000004','view'),
 ('30000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000004','view'),
 ('30000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000005','view'),
 ('30000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000005','view'),
 ('30000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000005','view'),
 ('30000000-0000-0000-0000-000000000004','00000000-0000-0000-0000-000000000005','view');

insert into documents (id, folder_id, aircraft_id, work_order_id, title, status, current_rev, created_by) values
 ('40000000-0000-0000-0000-000000000001','30000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000001','20000000-0000-0000-0000-000000000001','Task card 1042','signed',2,'00000000-0000-0000-0000-000000000003'),
 ('40000000-0000-0000-0000-000000000002','30000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000001','20000000-0000-0000-0000-000000000001','Task card 1043','awaiting_signature',1,'00000000-0000-0000-0000-000000000003'),
 ('40000000-0000-0000-0000-000000000003','30000000-0000-0000-0000-000000000002',null,null,'Maintenance manual','signed',7,'00000000-0000-0000-0000-000000000001'),
 ('40000000-0000-0000-0000-000000000004','30000000-0000-0000-0000-000000000003','10000000-0000-0000-0000-000000000002','20000000-0000-0000-0000-000000000002','Technical log 2026-10-26','awaiting_signature',1,'00000000-0000-0000-0000-000000000003'),
 ('40000000-0000-0000-0000-000000000005','30000000-0000-0000-0000-000000000004','10000000-0000-0000-0000-000000000001','20000000-0000-0000-0000-000000000001','Certificate of release 118','signed',1,'00000000-0000-0000-0000-000000000002');

insert into document_revisions (document_id, revision, file_path, note, uploaded_by) values
 ('40000000-0000-0000-0000-000000000001',1,'task-cards/1042_v1.pdf','First scan',          '00000000-0000-0000-0000-000000000003'),
 ('40000000-0000-0000-0000-000000000001',2,'task-cards/1042_v2.pdf','Corrected torque value','00000000-0000-0000-0000-000000000003'),
 ('40000000-0000-0000-0000-000000000002',1,'task-cards/1043_v1.pdf','First scan',          '00000000-0000-0000-0000-000000000003'),
 ('40000000-0000-0000-0000-000000000003',7,'manuals/mm_rev7.pdf',   'Revision 7',          '00000000-0000-0000-0000-000000000001'),
 ('40000000-0000-0000-0000-000000000004',1,'tech-logs/2026-10-26.pdf','Daily log',         '00000000-0000-0000-0000-000000000003'),
 ('40000000-0000-0000-0000-000000000005',1,'releases/crs_118.pdf',  'Release certificate', '00000000-0000-0000-0000-000000000002');

insert into signatures (document_id, revision, signed_by) values
 ('40000000-0000-0000-0000-000000000001',2,'00000000-0000-0000-0000-000000000002'),
 ('40000000-0000-0000-0000-000000000005',1,'00000000-0000-0000-0000-000000000002');

insert into access_requests (folder_id, profile_id, reason) values
 ('30000000-0000-0000-0000-000000000004','00000000-0000-0000-0000-000000000003','Need to read releases for ZS-XXX');

insert into notifications (profile_id, message) values
 ('00000000-0000-0000-0000-000000000002','Task card 1043 is waiting for your signature'),
 ('00000000-0000-0000-0000-000000000002','Technical log 2026-10-26 is waiting for your signature'),
 ('00000000-0000-0000-0000-000000000001','Test Technician asked for access to Releases (CRS)');

insert into devices (profile_id, name) values
 ('00000000-0000-0000-0000-000000000002','Phone · App'),
 ('00000000-0000-0000-0000-000000000001','Laptop · Browser');

insert into activity_log (at, profile_id, action, target, device, result) values
 (now() - interval '1 minute',  '00000000-0000-0000-0000-000000000002','Signed',        'Task card 1042 (v2)',         'Phone · App',     'ok'),
 (now() - interval '27 minutes','00000000-0000-0000-0000-000000000003','Viewed',        'Maintenance manual Rev 7',    'Phone · App',     'ok'),
 (now() - interval '44 minutes','00000000-0000-0000-0000-000000000003','Tried to open', 'Releases (CRS)',              'Phone · App',     'denied'),
 (now() - interval '72 minutes','00000000-0000-0000-0000-000000000001','Changed access','Test Technician · Releases',  'Laptop · Browser','ok'),
 (now() - interval '107 minutes','00000000-0000-0000-0000-000000000004','Downloaded',   'Parts certificate 118',       'Laptop · Browser','ok'),
 (now() - interval '150 minutes','00000000-0000-0000-0000-000000000005','Signed in',    null,                          'Laptop · Browser','ok');

-- =====================================================================
-- TO TEST LOGIN: Supabase > Authentication > Users > Add user, using one
-- of the emails above (e.g. admin@example.com) with "Auto confirm" on.
-- The trigger links it to the matching profile automatically.
-- For files, create a private Storage bucket named: records
-- =====================================================================

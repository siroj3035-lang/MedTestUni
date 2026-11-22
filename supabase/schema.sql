-- ============================================================
-- МедТест: база данных и серверная логика (Supabase)
-- Выполните ОДИН раз: Supabase → SQL Editor → New query → вставить → Run
-- Скрипт безопасно запускать повторно (данные не удаляются).
-- ============================================================

create extension if not exists pgcrypto with schema extensions;
create schema if not exists app;   -- закрытая схема: прямого доступа из браузера нет

-- ---------- Таблицы ----------
create table if not exists app.users (
  id bigint generated always as identity primary key,
  login text not null unique check (login ~ '^[a-z0-9_.-]{3,30}$'),
  name text not null check (char_length(name) between 1 and 60),
  pass_hash text not null,
  is_admin boolean not null default false,
  failed int not null default 0,
  locked_until timestamptz,
  created_at timestamptz not null default now()
);
create table if not exists app.sessions (
  token_hash text primary key,
  user_id bigint not null references app.users(id) on delete cascade,
  expires_at timestamptz not null
);
create table if not exists app.topics (
  id bigint generated always as identity primary key,
  subject text not null,
  name text not null,
  faculty text,
  course int check (course between 1 and 6),
  unique (subject, name)
);
create table if not exists app.questions (
  id bigint generated always as identity primary key,
  topic_id bigint not null references app.topics(id) on delete cascade,
  lang text not null check (lang in ('ru','uz')),
  type text not null check (type in ('test','case')),
  case_text text,
  text text not null,
  options jsonb not null,
  answer int not null
);
create index if not exists idx_questions_topic on app.questions (topic_id, lang, type);
create table if not exists app.attempts (
  id bigint generated always as identity primary key,
  user_id bigint not null references app.users(id) on delete cascade,
  topic_id bigint not null references app.topics(id) on delete cascade,
  mode text not null check (mode in ('test','case','control')),
  lang text not null,
  total int not null,
  correct int not null,
  seconds int not null default 0,
  created_at timestamptz not null default now()
);
create index if not exists idx_attempts_user on app.attempts (user_id, topic_id);
create table if not exists app.attempt_answers (
  attempt_id bigint not null references app.attempts(id) on delete cascade,
  question_id bigint not null references app.questions(id) on delete cascade,
  chosen int,
  is_correct boolean not null,
  primary key (attempt_id, question_id)
);

revoke all on schema app from public;
do $$ begin
  if exists (select 1 from pg_roles where rolname = 'anon') then
    revoke all on schema app from anon;
    revoke all on all tables in schema app from anon;
  end if;
  if exists (select 1 from pg_roles where rolname = 'authenticated') then
    revoke all on schema app from authenticated;
    revoke all on all tables in schema app from authenticated;
  end if;
end $$;

-- ---------- Внутренние функции (недоступны из браузера) ----------
create or replace function app.uid(p_token text) returns bigint
language plpgsql security definer set search_path = app, extensions, public as $$
declare v bigint;
begin
  select s.user_id into v from app.sessions s
   where s.token_hash = encode(digest(coalesce(p_token, ''), 'sha256'), 'hex') and s.expires_at > now();
  if v is null then raise exception 'Сессия истекла, войдите снова'; end if;
  return v;
end $$;

create or replace function app.require_admin(p_token text) returns bigint
language plpgsql security definer set search_path = app, extensions, public as $$
declare v bigint := app.uid(p_token);
begin
  if not (select is_admin from app.users where id = v) then raise exception 'Нужны права администратора'; end if;
  return v;
end $$;

create or replace function app.new_session(p_user bigint) returns text
language plpgsql security definer set search_path = app, extensions, public as $$
declare v_token text := encode(gen_random_bytes(32), 'hex');
begin
  delete from app.sessions where expires_at < now();
  insert into app.sessions (token_hash, user_id, expires_at)
  values (encode(digest(v_token, 'sha256'), 'hex'), p_user, now() + interval '30 days');
  return v_token;
end $$;

-- ---------- API: аккаунты ----------
create or replace function public.api_register(p_login text, p_password text, p_name text) returns jsonb
language plpgsql security definer set search_path = app, extensions, public as $$
declare
  v_login text := lower(trim(coalesce(p_login, '')));
  v_name text := trim(coalesce(p_name, ''));
  v_id bigint; v_admin boolean;
begin
  if v_name = '' or char_length(v_name) > 60 then raise exception 'Введите фамилию и имя (до 60 символов)'; end if;
  if v_login !~ '^[a-z0-9_.-]{3,30}$' then raise exception 'Логин: 3–30 символов, латиница, цифры, _ . -'; end if;
  if p_password is null or char_length(p_password) < 6 or char_length(p_password) > 72 then
    raise exception 'Пароль: от 6 до 72 символов';
  end if;
  lock table app.users in share row exclusive mode;
  if exists (select 1 from app.users where login = v_login) then raise exception 'Такой логин уже занят'; end if;
  v_admin := not exists (select 1 from app.users);   -- первый аккаунт становится администратором
  insert into app.users (login, name, pass_hash, is_admin)
  values (v_login, v_name, crypt(p_password, gen_salt('bf', 10)), v_admin) returning id into v_id;
  return jsonb_build_object('token', app.new_session(v_id),
    'user', jsonb_build_object('id', v_id, 'login', v_login, 'name', v_name, 'is_admin', v_admin));
end $$;

create or replace function public.api_login(p_login text, p_password text) returns jsonb
language plpgsql security definer set search_path = app, extensions, public as $$
declare u app.users;
begin
  select * into u from app.users where login = lower(trim(coalesce(p_login, '')));
  if found and u.locked_until is not null and u.locked_until > now() then
    return jsonb_build_object('error', 'Слишком много неудачных попыток. Попробуйте через 10 минут');
  end if;
  if not found then
    perform crypt(coalesce(p_password, ''), gen_salt('bf', 10));   -- одинаковое время ответа
    return jsonb_build_object('error', 'Неверный логин или пароль');
  end if;
  if u.pass_hash <> crypt(coalesce(p_password, ''), u.pass_hash) then
    update app.users set
      locked_until = case when failed + 1 >= 5 then now() + interval '10 minutes' else locked_until end,
      failed = case when failed + 1 >= 5 then 0 else failed + 1 end
    where id = u.id;
    return jsonb_build_object('error', 'Неверный логин или пароль');
  end if;
  update app.users set failed = 0, locked_until = null where id = u.id;
  return jsonb_build_object('token', app.new_session(u.id),
    'user', jsonb_build_object('id', u.id, 'login', u.login, 'name', u.name, 'is_admin', u.is_admin));
end $$;

create or replace function public.api_me(p_token text) returns jsonb
language plpgsql security definer set search_path = app, extensions, public as $$
declare v bigint := app.uid(p_token);
begin
  return (select jsonb_build_object('id', id, 'login', login, 'name', name, 'is_admin', is_admin) from app.users where id = v);
end $$;

create or replace function public.api_logout(p_token text) returns boolean
language plpgsql security definer set search_path = app, extensions, public as $$
begin
  delete from app.sessions where token_hash = encode(digest(coalesce(p_token, ''), 'sha256'), 'hex');
  return true;
end $$;

-- ---------- API: темы, вопросы, результаты ----------
create or replace function public.api_topics(p_token text, p_subject text, p_lang text, p_faculty text, p_course int) returns jsonb
language plpgsql security definer set search_path = app, extensions, public as $$
begin
  perform app.uid(p_token);
  return coalesce((
    select jsonb_agg(jsonb_build_object('id', t.id, 'subject', t.subject, 'name', t.name, 'faculty', t.faculty, 'course', t.course,
             'tests', coalesce(c.tests, 0), 'cases', coalesce(c.cases, 0)) order by t.name)
    from app.topics t
    left join (select topic_id, count(*) filter (where type = 'test') tests, count(*) filter (where type = 'case') cases
               from app.questions where lang = p_lang group by topic_id) c on c.topic_id = t.id
    where t.subject = p_subject
      and (p_faculty is null or t.faculty is null or t.faculty = p_faculty)
      and (p_course is null or t.course is null or t.course = p_course)
  ), '[]'::jsonb);
end $$;

-- Вопросы отдаются БЕЗ правильных ответов
create or replace function public.api_questions(p_token text, p_topic bigint, p_mode text, p_lang text) returns jsonb
language plpgsql security definer set search_path = app, extensions, public as $$
begin
  perform app.uid(p_token);
  if p_mode not in ('test', 'case', 'control') then raise exception 'Неизвестный режим'; end if;
  return coalesce((
    select jsonb_agg(jsonb_build_object('id', x.id, 'type', x.type, 'case', x.case_text, 'text', x.text, 'options', x.options) order by x.ord)
    from (select q.*, case when p_mode = 'control' then random() else q.id::float8 end as ord
          from app.questions q
          where q.topic_id = p_topic and q.lang = p_lang and (p_mode = 'control' or q.type = p_mode)) x
  ), '[]'::jsonb);
end $$;

create or replace function public.api_submit(p_token text, p_topic bigint, p_mode text, p_lang text, p_seconds int, p_answers jsonb) returns jsonb
language plpgsql security definer set search_path = app, extensions, public as $$
declare v_uid bigint; v_n int; v_total int; v_ok int; v_att bigint; v_wrong jsonb;
begin
  v_uid := app.uid(p_token);
  if p_mode not in ('test', 'case', 'control') then raise exception 'Неизвестный режим'; end if;
  if p_answers is null or jsonb_typeof(p_answers) <> 'array' or jsonb_array_length(p_answers) not between 1 and 500 then
    raise exception 'Нет ответов';
  end if;
  if not exists (select 1 from app.topics where id = p_topic) then raise exception 'Тема не найдена'; end if;

  drop table if exists pg_temp._att;
  create temp table _att on commit drop as
    select (e->>'questionId')::bigint as qid, (e->>'chosen')::int as chosen, ord
    from jsonb_array_elements(p_answers) with ordinality as t(e, ord);

  select count(*), count(distinct qid) into v_n, v_total from _att;
  if v_n <> v_total then raise exception 'Повторяющиеся вопросы'; end if;
  if exists (select 1 from _att a left join app.questions q on q.id = a.qid and q.topic_id = p_topic and q.lang = p_lang where q.id is null) then
    raise exception 'Вопросы не относятся к этой теме';
  end if;
  if exists (select 1 from _att a join app.questions q on q.id = a.qid
             where (p_mode = 'test' and q.type <> 'test') or (p_mode = 'case' and q.type <> 'case')) then
    raise exception 'Вопросы не соответствуют режиму';
  end if;
  if exists (select 1 from _att a join app.questions q on q.id = a.qid
             where a.chosen is not null and (a.chosen < 0 or a.chosen >= jsonb_array_length(q.options))) then
    raise exception 'Некорректный вариант ответа';
  end if;

  select count(*) into v_ok from _att a join app.questions q on q.id = a.qid where a.chosen = q.answer;
  insert into app.attempts (user_id, topic_id, mode, lang, total, correct, seconds)
  values (v_uid, p_topic, p_mode, p_lang, v_n, v_ok, least(greatest(coalesce(p_seconds, 0), 0), 86400)) returning id into v_att;
  insert into app.attempt_answers (attempt_id, question_id, chosen, is_correct)
    select v_att, a.qid, a.chosen, (a.chosen = q.answer) is true from _att a join app.questions q on q.id = a.qid;
  select coalesce(jsonb_agg(jsonb_build_object('id', q.id, 'case', q.case_text, 'text', q.text, 'options', q.options,
                  'correct', q.answer, 'chosen', a.chosen) order by a.ord), '[]'::jsonb)
    into v_wrong from _att a join app.questions q on q.id = a.qid where a.chosen is distinct from q.answer;
  return jsonb_build_object('attemptId', v_att, 'total', v_n, 'correct', v_ok, 'pct', round(100.0 * v_ok / v_n), 'wrong', v_wrong);
end $$;

create or replace function public.api_stats(p_token text) returns jsonb
language plpgsql security definer set search_path = app, extensions, public as $$
declare v_uid bigint := app.uid(p_token);
begin
  return (
    with att as (select a.*, round(100.0 * a.correct / a.total)::int as pct from app.attempts a where a.user_id = v_uid),
    md as (select topic_id, mode, count(*) n, max(pct) best, (array_agg(pct order by id desc))[1] last from att group by topic_id, mode),
    ag as (select topic_id, count(*) attempts, max(pct) best, (array_agg(pct order by id desc))[1] last,
                  sum(total) tot, sum(total - correct) wr, max(created_at) last_at from att group by topic_id)
    select coalesce(jsonb_agg(jsonb_build_object('id', t.id, 'subject', t.subject, 'name', t.name, 'course', t.course,
        'attempts', coalesce(g.attempts, 0), 'best', coalesce(g.best, 0), 'last', coalesce(g.last, 0),
        'tot', coalesce(g.tot, 0), 'wr', coalesce(g.wr, 0), 'lastAt', g.last_at,
        'modes', coalesce((select jsonb_object_agg(m.mode, jsonb_build_object('n', m.n, 'best', m.best, 'last', m.last))
                           from md m where m.topic_id = t.id), '{}'::jsonb)) order by t.subject, t.name), '[]'::jsonb)
    from app.topics t left join ag g on g.topic_id = t.id
  );
end $$;

-- ---------- API: администратор ----------
create or replace function public.api_admin_import(p_token text, p_data jsonb) returns jsonb
language plpgsql security definer set search_path = app, extensions, public as $$
declare
  v_list jsonb; t jsonb; q jsonb; i int; j int; v_topic bigint; v_out jsonb := '[]'::jsonb;
  v_name text; v_lang text; v_course int; v_n int;
begin
  perform app.require_admin(p_token);
  v_list := case jsonb_typeof(p_data)
              when 'array' then p_data
              when 'object' then case when p_data ? 'topics' then p_data->'topics' else jsonb_build_array(p_data) end
            end;
  if v_list is null or jsonb_array_length(v_list) = 0 then raise exception 'Нет данных для загрузки'; end if;
  for i in 0 .. jsonb_array_length(v_list) - 1 loop
    t := v_list->i;
    v_name := trim(coalesce(t->>'topic', ''));
    v_lang := t->>'lang';
    if trim(coalesce(t->>'subject', '')) = '' then raise exception 'Не указан предмет'; end if;
    if v_name = '' or char_length(v_name) > 200 then raise exception 'Не указано название темы'; end if;
    if v_lang is null or v_lang not in ('ru', 'uz') then raise exception 'Язык должен быть ru или uz'; end if;
    v_course := nullif(t->>'course', '')::int;
    if v_course is not null and v_course not between 1 and 6 then raise exception 'Курс: от 1 до 6'; end if;
    if jsonb_typeof(t->'questions') <> 'array' or jsonb_array_length(t->'questions') = 0 then raise exception 'Нет вопросов'; end if;

    insert into app.topics (subject, name, faculty, course)
    values (trim(t->>'subject'), v_name, nullif(t->>'faculty', ''), v_course)
    on conflict (subject, name) do update
      set faculty = coalesce(excluded.faculty, app.topics.faculty), course = coalesce(excluded.course, app.topics.course)
    returning id into v_topic;
    if coalesce((t->>'replace')::boolean, false) then
      delete from app.questions where topic_id = v_topic and lang = v_lang;
    end if;

    v_n := jsonb_array_length(t->'questions');
    for j in 0 .. v_n - 1 loop
      q := (t->'questions')->j;
      if coalesce(q->>'type', '') not in ('test', 'case') then raise exception 'Вопрос %: тип должен быть test или case', j + 1; end if;
      if trim(coalesce(q->>'q', '')) = '' then raise exception 'Вопрос %: нет текста', j + 1; end if;
      if jsonb_typeof(q->'options') <> 'array' or jsonb_array_length(q->'options') not between 2 and 6
         or exists (select 1 from jsonb_array_elements(q->'options') o where jsonb_typeof(o) <> 'string' or trim(o #>> '{}') = '') then
        raise exception 'Вопрос %: нужно от 2 до 6 непустых вариантов', j + 1;
      end if;
      if jsonb_typeof(q->'answer') <> 'number' or (q->>'answer')::numeric <> floor((q->>'answer')::numeric)
         or (q->>'answer')::int not between 0 and jsonb_array_length(q->'options') - 1 then
        raise exception 'Вопрос %: не указан правильный вариант', j + 1;
      end if;
      insert into app.questions (topic_id, lang, type, case_text, text, options, answer)
      values (v_topic, v_lang, q->>'type',
              case when q->>'type' = 'case' then nullif(trim(coalesce(q->>'case', '')), '') end,
              trim(q->>'q'), q->'options', (q->>'answer')::int);
    end loop;
    v_out := v_out || jsonb_build_object('subject', t->>'subject', 'topic', v_name, 'lang', v_lang, 'added', v_n);
  end loop;
  return v_out;
end $$;

create or replace function public.api_admin_topics(p_token text) returns jsonb
language plpgsql security definer set search_path = app, extensions, public as $$
begin
  perform app.require_admin(p_token);
  return coalesce((
    select jsonb_agg(jsonb_build_object('id', x.id, 'subject', x.subject, 'name', x.name, 'course', x.course,
      'ru_tests', x.ru_tests, 'ru_cases', x.ru_cases, 'uz_tests', x.uz_tests, 'uz_cases', x.uz_cases) order by x.subject, x.name)
    from (
      select t.id, t.subject, t.name, t.course,
        count(q.id) filter (where q.lang = 'ru' and q.type = 'test') as ru_tests,
        count(q.id) filter (where q.lang = 'ru' and q.type = 'case') as ru_cases,
        count(q.id) filter (where q.lang = 'uz' and q.type = 'test') as uz_tests,
        count(q.id) filter (where q.lang = 'uz' and q.type = 'case') as uz_cases
      from app.topics t left join app.questions q on q.topic_id = t.id group by t.id
    ) x
  ), '[]'::jsonb);
end $$;

create or replace function public.api_admin_questions(p_token text, p_topic bigint) returns jsonb
language plpgsql security definer set search_path = app, extensions, public as $$
begin
  perform app.require_admin(p_token);
  return coalesce((select jsonb_agg(jsonb_build_object('id', id, 'lang', lang, 'type', type, 'case', case_text, 'text', text,
                   'options', options, 'answer', answer) order by lang, id) from app.questions where topic_id = p_topic), '[]'::jsonb);
end $$;

create or replace function public.api_admin_delete_question(p_token text, p_id bigint) returns boolean
language plpgsql security definer set search_path = app, extensions, public as $$
begin
  perform app.require_admin(p_token);
  delete from app.questions where id = p_id;
  return true;
end $$;

create or replace function public.api_admin_delete_topic(p_token text, p_id bigint) returns boolean
language plpgsql security definer set search_path = app, extensions, public as $$
begin
  perform app.require_admin(p_token);
  delete from app.topics where id = p_id;
  return true;
end $$;

-- ---------- Права: браузеру доступны только функции api_* ----------
do $$
declare r record;
begin
  for r in select p.oid::regprocedure as sig from pg_proc p join pg_namespace n on n.oid = p.pronamespace
           where n.nspname = 'public' and p.proname like 'api\_%' loop
    execute format('revoke all on function %s from public', r.sig);
    if exists (select 1 from pg_roles where rolname = 'anon') then
      execute format('grant execute on function %s to anon', r.sig);
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
      execute format('grant execute on function %s to authenticated', r.sig);
    end if;
  end loop;
end $$;

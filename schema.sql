-- =========================================================
-- 물결 MVP 데이터베이스
-- Supabase 대시보드 > SQL Editor 에 전체를 붙여넣고 Run 한 번
-- =========================================================

create extension if not exists pgcrypto;

-- ---------- 테이블 ----------

-- 강사 (회원가입하면 자동으로 한 줄 생김)
create table if not exists public.teachers (
  id uuid primary key references auth.users(id) on delete cascade,
  name text not null,
  created_at timestamptz not null default now()
);

-- 표준 드릴 목록 (영법·단계별)
create table if not exists public.drills (
  id serial primary key,
  level text not null,          -- 예: '자유형 2단계'
  level_order int not null,     -- 단계 정렬 순서
  name text not null,           -- 예: '측면 호흡'
  sort int not null             -- 단계 안에서의 순서
);

-- 반
create table if not exists public.classes (
  id uuid primary key default gen_random_uuid(),
  teacher_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  name text not null,           -- 예: '중급반'
  schedule text,                -- 예: '화목 17:00'
  created_at timestamptz not null default now()
);

-- 회원(아이)
create table if not exists public.students (
  id uuid primary key default gen_random_uuid(),
  class_id uuid not null references public.classes(id) on delete cascade,
  name text not null,
  age int,
  level text not null,
  report_token uuid not null unique default gen_random_uuid(),  -- 학부모 리포트 링크용 비밀 키
  created_at timestamptz not null default now()
);

-- 수업 1회 기록 (코멘트·영상)
create table if not exists public.sessions (
  id uuid primary key default gen_random_uuid(),
  student_id uuid not null references public.students(id) on delete cascade,
  lesson_date date not null default current_date,
  comment text,
  video_path text,
  input_seconds int,            -- 강사가 이 회원 기록에 쓴 시간(초): 입력 부담 기준 마련용
  created_at timestamptz not null default now(),
  unique (student_id, lesson_date)
);

-- 드릴별 체크 (완료 / 진행 / 미실시)
create table if not exists public.records (
  id bigserial primary key,
  student_id uuid not null references public.students(id) on delete cascade,
  drill_id int not null references public.drills(id),
  lesson_date date not null,
  status text not null check (status in ('done', 'doing', 'none')),
  unique (student_id, drill_id, lesson_date)
);

-- 학부모 체감도 설문
create table if not exists public.surveys (
  id bigserial primary key,
  student_id uuid not null references public.students(id) on delete cascade,
  answer text not null check (answer in ('yes', 'same', 'no')),
  created_at timestamptz not null default now()
);

-- ---------- 회원가입 시 강사 정보 자동 생성 ----------

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.teachers (id, name)
  values (new.id, coalesce(new.raw_user_meta_data ->> 'name', '강사'));
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ---------- 보안 규칙 (강사는 자기 반·회원만 보고 고칠 수 있음) ----------

alter table public.teachers enable row level security;
alter table public.drills   enable row level security;
alter table public.classes  enable row level security;
alter table public.students enable row level security;
alter table public.sessions enable row level security;
alter table public.records  enable row level security;
alter table public.surveys  enable row level security;

create or replace function public.owns_student(sid uuid)
returns boolean language sql security definer stable set search_path = public as $$
  select exists (
    select 1 from students s join classes c on c.id = s.class_id
    where s.id = sid and c.teacher_id = auth.uid()
  );
$$;

create policy "teacher: own row" on public.teachers
  for all to authenticated using (id = auth.uid()) with check (id = auth.uid());

create policy "drills: read" on public.drills
  for select to authenticated using (true);

create policy "classes: own" on public.classes
  for all to authenticated using (teacher_id = auth.uid()) with check (teacher_id = auth.uid());

create policy "students: own" on public.students
  for all to authenticated
  using (exists (select 1 from classes c where c.id = class_id and c.teacher_id = auth.uid()))
  with check (exists (select 1 from classes c where c.id = class_id and c.teacher_id = auth.uid()));

create policy "sessions: own" on public.sessions
  for all to authenticated using (owns_student(student_id)) with check (owns_student(student_id));

create policy "records: own" on public.records
  for all to authenticated using (owns_student(student_id)) with check (owns_student(student_id));

create policy "surveys: own read" on public.surveys
  for select to authenticated using (owns_student(student_id));

-- ---------- 학부모용: 로그인 없이 링크(비밀 키)로만 리포트 조회 ----------

create or replace function public.get_report(p_token uuid)
returns json language sql security definer stable set search_path = public as $$
  select json_build_object(
    'student',      json_build_object('name', s.name, 'age', s.age, 'level', s.level),
    'class_name',   c.name,
    'teacher_name', t.name,
    'drills',   (select coalesce(json_agg(json_build_object('id', d.id, 'name', d.name) order by d.sort), '[]'::json)
                 from drills d where d.level = s.level),
    'records',  (select coalesce(json_agg(json_build_object('drill_id', r.drill_id, 'date', r.lesson_date, 'status', r.status)
                 order by r.lesson_date), '[]'::json)
                 from records r where r.student_id = s.id),
    'sessions', (select coalesce(json_agg(json_build_object('date', x.lesson_date, 'comment', x.comment, 'video_path', x.video_path)
                 order by x.lesson_date), '[]'::json)
                 from sessions x where x.student_id = s.id)
  )
  from students s
  join classes c on c.id = s.class_id
  left join teachers t on t.id = c.teacher_id
  where s.report_token = p_token;
$$;

create or replace function public.submit_survey(p_token uuid, p_answer text)
returns void language plpgsql security definer set search_path = public as $$
begin
  insert into surveys (student_id, answer)
  select id, p_answer from students where report_token = p_token;
end $$;

grant execute on function public.get_report(uuid) to anon, authenticated;
grant execute on function public.submit_survey(uuid, text) to anon, authenticated;

-- ---------- 영상 저장소 ----------
-- 영상 주소에 아이별 비밀 키가 들어가서, 리포트 링크를 받은 사람만 볼 수 있음
-- (목록 조회는 막혀 있어 다른 아이 영상을 찾아볼 수 없음)

insert into storage.buckets (id, name, public, file_size_limit)
values ('videos', 'videos', true, 52428800)   -- 1개 최대 50MB
on conflict (id) do nothing;

create policy "videos: teachers upload" on storage.objects
  for insert to authenticated with check (bucket_id = 'videos');

-- ---------- 표준 드릴 목록 (초기값, 자유롭게 고쳐서 사용) ----------

insert into public.drills (level, level_order, name, sort) values
  ('자유형 1단계', 1, '물 적응 · 음파 호흡',        1),
  ('자유형 1단계', 1, '벽 잡고 발차기',             2),
  ('자유형 1단계', 1, '킥판 발차기',                3),
  ('자유형 1단계', 1, '킥판 발차기 + 정면 호흡',    4),
  ('자유형 2단계', 2, '킥판 측면 호흡',             1),
  ('자유형 2단계', 2, '한 팔 자유형 (킥판)',        2),
  ('자유형 2단계', 2, '자유형 팔 동작',             3),
  ('자유형 2단계', 2, '팔 동작 + 호흡 맞추기',      4),
  ('자유형 2단계', 2, '자유형 12.5m',               5),
  ('자유형 3단계', 3, '자유형 25m 완주',            1),
  ('자유형 3단계', 3, '양측 호흡',                  2),
  ('자유형 3단계', 3, '스트림라인 출발',            3),
  ('배영 1단계',   4, '누워 뜨기',                  1),
  ('배영 1단계',   4, '배영 발차기 (킥판 안고)',    2),
  ('배영 1단계',   4, '배영 발차기 12.5m',          3),
  ('배영 2단계',   5, '배영 한 팔 동작',            1),
  ('배영 2단계',   5, '배영 팔 동작',               2),
  ('배영 2단계',   5, '배영 25m 완주',              3);

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import sys
import traceback
import urllib.parse
from datetime import date, datetime
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "diary.db")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")

HOST = "127.0.0.1"
PORT = 5000

DAYS = ["Понедельник", "Вторник", "Среда", "Четверг", "Пятница", "Суббота"]
WEEKDAY_MAP = {0: "Понедельник", 1: "Вторник", 2: "Среда",
               3: "Четверг", 4: "Пятница", 5: "Суббота"}

ROLES = ("student", "teacher")
ROLE_LABELS = {"student": "ученик", "teacher": "учитель"}

SESSIONS = {}


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT    NOT NULL UNIQUE,
            email      TEXT    NOT NULL UNIQUE,
            password   TEXT    NOT NULL,
            role       TEXT    NOT NULL DEFAULT 'student'
                              CHECK (role IN ('student', 'teacher')),
            created_at TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS schedule (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id       INTEGER NOT NULL,
            day           TEXT    NOT NULL,
            lesson_number INTEGER NOT NULL,
            subject       TEXT    NOT NULL,
            teacher       TEXT,
            room          TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS grades (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            subject TEXT    NOT NULL,
            grade   INTEGER NOT NULL CHECK (grade BETWEEN 2 AND 5),
            date    TEXT    NOT NULL,
            comment TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_schedule_user ON schedule (user_id, day);
        CREATE INDEX IF NOT EXISTS idx_grades_user   ON grades (user_id, date);
        """
    )
    conn.commit()
    conn.close()

PBKDF2_ITERATIONS = 100_000


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                             bytes.fromhex(salt), PBKDF2_ITERATIONS)
    return f"{salt}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, hash_hex = stored.split("$", 1)
        salt = bytes.fromhex(salt_hex)
    except (ValueError, TypeError):
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                             salt, PBKDF2_ITERATIONS)
    return hmac.compare_digest(dk.hex(), hash_hex)

def esc(value) -> str:
    if value is None:
        return ""
    return (str(value)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;"))

_PLACEHOLDER = re.compile(r"\{\{\s*(\w+)\s*\}\}")

def render_template(name: str, **context) -> str:
    with open(os.path.join(TEMPLATES_DIR, name), encoding="utf-8") as f:
        html = f.read()

    def repl(match: re.Match) -> str:
        return str(context.get(match.group(1), ""))

    return _PLACEHOLDER.sub(repl, html)

class DiaryHandler(BaseHTTPRequestHandler):
    server_version = "DiaryHTTP/1.0"
    _form_cache = None

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))

    def _dispatch(self, method: str):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        self.query_params = {k: v[0] for k, v in
                             urllib.parse.parse_qs(parsed.query).items()}

        self.session, self.token = self._ensure_session()
        self._form_cache = None

        try:
            if path.startswith("/static/"):
                return self._serve_static(path[len("/static/"):])

            routes = {
                ("GET",  "/"):                self.page_index,
                ("GET",  "/register"):        self.page_register,
                ("POST", "/register"):        self.page_register,
                ("GET",  "/login"):           self.page_login,
                ("POST", "/login"):           self.page_login,
                ("GET",  "/logout"):          self.page_logout,
                ("GET",  "/schedule"):        self.page_schedule,
                ("POST", "/schedule"):        self.page_schedule,
                ("POST", "/schedule/delete"): self.page_schedule_delete,
                ("GET",  "/grades"):          self.page_grades,
                ("POST", "/grades"):          self.page_grades,
                ("POST", "/grades/delete"):   self.page_grades_delete,
            }
            handler = routes.get((method, path))
            if handler is None:
                self._not_found()
            else:
                handler()
        except Exception:
            traceback.print_exc()
            self._server_error()

    def _ensure_session(self):
        cookie = SimpleCookie()
        if "Cookie" in self.headers:
            try:
                cookie.load(self.headers["Cookie"])
            except Exception:
                pass
        morsel = cookie.get("session_id")
        if morsel and morsel.value in SESSIONS:
            session = SESSIONS[morsel.value]
            session.setdefault("flash", [])
            return session, morsel.value

        token = secrets.token_urlsafe(24)
        SESSIONS[token] = {"user_id": None, "username": None,
                           "role": None, "flash": []}
        return SESSIONS[token], token

    def flash(self, category: str, message: str) -> None:
        self.session.setdefault("flash", []).append((category, message))

    def _render_flashes(self) -> str:
        flashes = self.session.get("flash") or []
        self.session["flash"] = []
        if not flashes:
            return ""
        inner = "".join(
            f'<div class="flash flash--{esc(cat)}">{esc(msg)}</div>'
            for cat, msg in flashes
        )
        return f'<div class="flash-area">{inner}</div>'

    def _build_nav(self) -> str:
        if not self.session.get("user_id"):
            return (
                '<a href="/login">Вход</a>'
                '<a class="btn" href="/register">Регистрация</a>'
            )

        role = self.session.get("role") or "student"
        if role == "teacher":
            items = '<a href="/">Ученики</a>'
        else:
            items = (
                '<a href="/">Главная</a>'
                '<a href="/schedule">Расписание</a>'
                '<a href="/grades">Оценки</a>'
            )
        return (
            items +
            f'<span class="user">👤 {esc(self.session["username"])}'
            f' <span class="role-badge role-badge--{role}">'
            f'{esc(ROLE_LABELS[role])}</span></span>'
            '<a class="btn btn--ghost" href="/logout">Выйти</a>'
        )

    def is_teacher(self) -> bool:
        return self.session.get("role") == "teacher"

    def is_student(self) -> bool:
        return self.session.get("role") == "student"

    def require_login(self) -> bool:
        if self.session.get("user_id"):
            return True
        self.flash("info", "Сначала войдите в аккаунт.")
        self.redirect("/login")
        return False

    def _read_form(self) -> dict:
        if self._form_cache is not None:
            return self._form_cache
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            length = 0
        if length <= 0:
            self._form_cache = {}
            return self._form_cache
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        self._form_cache = {k: v[0] for k, v in
                            urllib.parse.parse_qs(body).items()}
        return self._form_cache

    def _send_bytes(self, code, content_type, body, extra_headers=None):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header(
            "Set-Cookie",
            f"session_id={self.token}; Path=/; HttpOnly; SameSite=Lax",
        )
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _send_html(self, code: int, html: str) -> None:
        self._send_bytes(code, "text/html; charset=utf-8", html.encode("utf-8"))

    def redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header(
            "Set-Cookie",
            f"session_id={self.token}; Path=/; HttpOnly; SameSite=Lax",
        )
        self.end_headers()

    def _render_page(self, title: str, template: str, **ctx) -> str:
        body = render_template(template, **ctx)
        return render_template(
            "base.html",
            title=esc(title),
            nav=self._build_nav(),
            flashes=self._render_flashes(),
            content=body,
        )

    def _not_found(self) -> None:
        html = render_template(
            "base.html",
            title="404 · Дневник",
            nav=self._build_nav(),
            flashes=self._render_flashes(),
            content='<div class="card"><h1>404</h1>'
                    '<p class="muted">Страница не найдена.</p></div>',
        )
        self._send_html(404, html)

    def _server_error(self) -> None:
        html = render_template(
            "base.html",
            title="500 · Дневник",
            nav=self._build_nav(),
            flashes="",
            content='<div class="card"><h1>500</h1>'
                    '<p class="muted">Внутренняя ошибка сервера.</p></div>',
        )
        self._send_html(500, html)

    def _serve_static(self, rel: str) -> None:
        rel = rel.replace("\\", "/").lstrip("/")
        full = os.path.normpath(os.path.join(STATIC_DIR, rel))
        if not (full == STATIC_DIR or full.startswith(STATIC_DIR + os.sep)):
            self.send_error(404, "Not Found")
            return
        if not os.path.isfile(full):
            self.send_error(404, "Not Found")
            return

        ext = os.path.splitext(full)[1].lower()
        ctype = {
            ".css": "text/css; charset=utf-8",
            ".js":  "application/javascript; charset=utf-8",
            ".svg": "image/svg+xml",
            ".png": "image/png",
            ".ico": "image/x-icon",
        }.get(ext, "application/octet-stream")

        with open(full, "rb") as f:
            data = f.read()

        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


    def page_index(self):
        if not self.require_login():
            return
        if self.is_teacher():
            return self._teacher_home()
        return self._student_home()

    def _teacher_home(self):
        db = get_db()
        students = db.execute(
            "SELECT id, username, email FROM users "
            "WHERE role = 'student' ORDER BY username"
        ).fetchall()
        stats = db.execute(
            "SELECT "
            "(SELECT COUNT(*) FROM users WHERE role = 'student') AS students_count, "
            "(SELECT COUNT(*) FROM schedule) AS schedule_count, "
            "(SELECT COUNT(*) FROM grades) AS grades_count"
        ).fetchone()
        db.close()

        if students:
            rows = "".join(
                f"<tr>"
                f"<td><strong>{esc(s['username'])}</strong></td>"
                f'<td class="muted">{esc(s["email"])}</td>'
                f"<td>"
                f'<a class="link" href="/schedule?student={s["id"]}">Расписание</a>'
                f' · <a class="link" href="/grades?student={s["id"]}">Оценки</a>'
                f"</td></tr>"
                for s in students
            )
            students_table = (
                "<table><thead><tr><th>Имя</th><th>Email</th>"
                "<th>Дневник</th></tr></thead>"
                f"<tbody>{rows}</tbody></table>"
            )
        else:
            students_table = (
                '<p class="muted">Пока нет ни одного ученика. '
                'Попросите их зарегистрироваться.</p>'
            )

        html = self._render_page(
            "Кабинет учителя · Дневник",
            "teacher_home.html",
            username=esc(self.session["username"]),
            students_count=stats["students_count"],
            schedule_count=stats["schedule_count"],
            grades_count=stats["grades_count"],
            students_table=students_table,
        )
        self._send_html(200, html)

    def _student_home(self):
        uid = self.session["user_id"]
        db = get_db()

        today = date.today()
        today_name = WEEKDAY_MAP.get(today.weekday())

        lessons = []
        if today_name:
            lessons = db.execute(
                "SELECT * FROM schedule WHERE user_id = ? AND day = ? "
                "ORDER BY lesson_number",
                (uid, today_name),
            ).fetchall()

        grades = db.execute(
            "SELECT * FROM grades WHERE user_id = ? "
            "ORDER BY date DESC, id DESC LIMIT 5",
            (uid,),
        ).fetchall()

        row = db.execute(
            "SELECT AVG(grade) AS avg_grade, COUNT(*) AS total "
            "FROM grades WHERE user_id = ?",
            (uid,),
        ).fetchone()
        db.close()

        avg = round(row["avg_grade"], 2) if row["avg_grade"] else "—"

        if lessons:
            rows = "".join(
                f"<tr><td>{l['lesson_number']}</td>"
                f"<td><strong>{esc(l['subject'])}</strong></td>"
                f"<td>{esc(l['teacher']) or '—'}</td>"
                f"<td>{esc(l['room']) or '—'}</td></tr>"
                for l in lessons
            )
            lessons_html = (
                "<table><thead><tr><th>№</th><th>Предмет</th>"
                "<th>Учитель</th><th>Кабинет</th></tr></thead>"
                f"<tbody>{rows}</tbody></table>"
            )
        else:
            lessons_html = '<p class="muted">На сегодня уроков нет 🎉</p>'

        if grades:
            items = "".join(
                f'<li><span class="grade grade--{g["grade"]}">{g["grade"]}</span>'
                f'<span class="grade-list__subject">{esc(g["subject"])}</span>'
                f'<span class="muted">{esc(g["date"])}'
                + (f' · {esc(g["comment"])}' if g["comment"] else "")
                + "</span></li>"
                for g in grades
            )
            grades_html = (
                f'<ul class="grade-list">{items}</ul>'
                '<a class="link" href="/grades">Все оценки →</a>'
            )
        else:
            grades_html = '<p class="muted">Оценок пока нет.</p>'

        html = self._render_page(
            "Главная · Дневник",
            "index.html",
            username=esc(self.session["username"]),
            today_date=today.strftime("%d.%m.%Y"),
            today_name_part=(f", {today_name}" if today_name else ""),
            avg=avg,
            count=row["total"],
            lessons_count=len(lessons),
            lessons_html=lessons_html,
            grades_html=grades_html,
        )
        self._send_html(200, html)

    def page_register(self):
        if self.session.get("user_id"):
            return self.redirect("/")

        form = {}
        if self.command == "POST":
            form = self._read_form()
            username = (form.get("username") or "").strip()
            email = (form.get("email") or "").strip().lower()
            password = form.get("password") or ""
            password2 = form.get("password2") or ""
            role = form.get("role") or "student"
            if role not in ROLES:
                role = "student"

            error = None
            if len(username) < 3:
                error = "Имя пользователя должно быть не короче 3 символов."
            elif "@" not in email or "." not in email:
                error = "Введите корректный email."
            elif len(password) < 6:
                error = "Пароль должен быть не короче 6 символов."
            elif password != password2:
                error = "Пароли не совпадают."

            if error is None:
                db = get_db()
                exists = db.execute(
                    "SELECT id FROM users WHERE username = ? OR email = ?",
                    (username, email),
                ).fetchone()
                if exists:
                    error = ("Пользователь с таким именем или email "
                             "уже существует.")
                else:
                    db.execute(
                        "INSERT INTO users "
                        "(username, email, password, role, created_at) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (username, email, hash_password(password), role,
                         datetime.now().isoformat(timespec="seconds")),
                    )
                    db.commit()
                    db.close()
                    self.flash("success",
                               "Регистрация прошла успешно! Теперь войдите.")
                    return self.redirect("/login")
                db.close()

            self.flash("error", error)

        html = self._render_page(
            "Регистрация · Дневник",
            "register.html",
            username=esc(form.get("username", "")),
            email=esc(form.get("email", "")),
            student_selected="selected" if form.get("role") != "teacher" else "",
            teacher_selected="selected" if form.get("role") == "teacher" else "",
        )
        self._send_html(200, html)

    def page_login(self):
        if self.session.get("user_id"):
            return self.redirect("/")

        form = {}
        if self.command == "POST":
            form = self._read_form()
            email = (form.get("email") or "").strip().lower()
            password = form.get("password") or ""

            db = get_db()
            user = db.execute(
                "SELECT * FROM users WHERE email = ?", (email,)
            ).fetchone()
            db.close()

            if user is None or not verify_password(password, user["password"]):
                self.flash("error", "Неверный email или пароль.")
            else:
                self.session["user_id"] = user["id"]
                self.session["username"] = user["username"]
                self.session["role"] = user["role"]
                self.flash("success",
                           f"Добро пожаловать, {user['username']}!")
                return self.redirect("/")

        html = self._render_page(
            "Вход · Дневник",
            "login.html",
            email=esc(form.get("email", "")),
        )
        self._send_html(200, html)

    def page_logout(self):
        self.session["user_id"] = None
        self.session["username"] = None
        self.session["role"] = None
        self.flash("info", "Вы вышли из аккаунта.")
        self.redirect("/login")


    def _resolve_target_student(self, form):
        """
        Возвращает (student, can_edit) или (None, None) если доступ запрещён.
        Для ученика — сам ученик, can_edit=False.
        Для учителя — ученик по student_id из формы или ?student=ID.
        """
        db = get_db()

        if self.is_student():
            student = db.execute(
                "SELECT * FROM users WHERE id = ? AND role = 'student'",
                (self.session["user_id"],),
            ).fetchone()
            db.close()
            return student, False

        if self.command == "POST":
            raw = (form or {}).get("student_id")
        else:
            raw = self.query_params.get("student")
        try:
            target_id = int(raw or 0)
        except (TypeError, ValueError):
            target_id = 0

        if not target_id:
            db.close()
            self.flash("error", "Выберите ученика.")
            self.redirect("/")
            return None, None

        student = db.execute(
            "SELECT * FROM users WHERE id = ? AND role = 'student'",
            (target_id,),
        ).fetchone()
        db.close()
        if not student:
            self.flash("error", "Ученик не найден.")
            self.redirect("/")
            return None, None

        return student, True

    def page_schedule(self):
        if not self.require_login():
            return

        form = self._read_form() if self.command == "POST" else {}
        student, can_edit = self._resolve_target_student(form)
        if student is None:
            return

        target_id = student["id"]
        db = get_db()

        if self.command == "POST":
            if not can_edit:
                db.close()
                self.flash("error", "Ученик не может менять расписание.")
                return self.redirect("/schedule")

            day = form.get("day", "")
            subject = (form.get("subject") or "").strip()
            teacher = (form.get("teacher") or "").strip()
            room = (form.get("room") or "").strip()
            try:
                num = int(form.get("lesson_number") or 0)
            except ValueError:
                num = 0

            if day not in DAYS:
                self.flash("error", "Некорректный день недели.")
            elif not subject:
                self.flash("error", "Укажите название предмета.")
            elif not 1 <= num <= 10:
                self.flash("error", "Номер урока должен быть от 1 до 10.")
            else:
                db.execute(
                    "INSERT INTO schedule "
                    "(user_id, day, lesson_number, subject, teacher, room) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (target_id, day, num, subject,
                     teacher or None, room or None),
                )
                db.commit()
                self.flash("success", "Урок добавлен в расписание.")
            db.close()
            return self.redirect(f"/schedule?student={target_id}")

        rows = db.execute(
            "SELECT * FROM schedule WHERE user_id = ? "
            "ORDER BY lesson_number, subject",
            (target_id,),
        ).fetchall()
        db.close()

        lessons_by_day = {d: [] for d in DAYS}
        for row in rows:
            lessons_by_day.setdefault(row["day"], []).append(row)

        blocks = []
        for day in DAYS:
            lessons = lessons_by_day.get(day, [])
            if lessons:
                body = ("<table><thead><tr>"
                        "<th>№</th><th>Предмет</th>"
                        "<th>Учитель</th><th>Кабинет</th>")
                if can_edit:
                    body += "<th></th>"
                body += "</tr></thead><tbody>"
                for l in lessons:
                    body += (
                        f"<tr><td>{l['lesson_number']}</td>"
                        f"<td><strong>{esc(l['subject'])}</strong></td>"
                        f"<td>{esc(l['teacher']) or '—'}</td>"
                        f"<td>{esc(l['room']) or '—'}</td>"
                    )
                    if can_edit:
                        body += (
                            f'<td><form method="post" '
                            f'action="/schedule/delete" '
                            f'class="inline js-confirm">'
                            f'<input type="hidden" name="id" value="{l["id"]}">'
                            f'<input type="hidden" name="student_id" '
                            f'value="{target_id}">'
                            f'<button class="btn btn--danger btn--small" '
                            f'type="submit">✕</button></form></td>'
                        )
                    body += "</tr>"
                body += "</tbody></table>"
            else:
                body = '<p class="muted">Уроков нет.</p>'
            blocks.append(
                f'<section class="card"><h2>{esc(day)}</h2>{body}</section>'
            )

        if can_edit:
            day_options = "".join(
                f'<option value="{esc(d)}">{esc(d)}</option>' for d in DAYS
            )
            add_section = (
                '<section class="card">'
                '<h2>Добавить урок</h2>'
                '<form method="post" action="/schedule" class="form form--grid">'
                f'<input type="hidden" name="student_id" value="{target_id}">'
                f'<label>День недели'
                f'<select name="day" required>{day_options}</select></label>'
                '<label>Номер урока'
                '<input type="number" name="lesson_number" min="1" max="10" '
                'value="1" required></label>'
                '<label>Предмет'
                '<input type="text" name="subject" maxlength="60" required>'
                '</label>'
                '<label>Учитель'
                '<input type="text" name="teacher" maxlength="60"></label>'
                '<label>Кабинет'
                '<input type="text" name="room" maxlength="20"></label>'
                '<button class="btn" type="submit">Добавить</button>'
                '</form></section>'
            )
            title_suffix = f'ученика: {esc(student["username"])}'
            back_link = ('<p class="muted">'
                         '<a href="/">← Назад к списку учеников</a></p>')
        else:
            add_section = ""
            title_suffix = "уроков"
            back_link = ""

        html = self._render_page(
            "Расписание · Дневник",
            "schedule.html",
            title_suffix=title_suffix,
            back_link=back_link,
            add_section=add_section,
            days_blocks="".join(blocks),
        )
        self._send_html(200, html)

    def page_schedule_delete(self):
        if not self.require_login():
            return
        if not self.is_teacher():
            self.flash("error", "Ученик не может менять расписание.")
            return self.redirect("/schedule")

        form = self._read_form()
        try:
            lesson_id = int(form.get("id") or 0)
            student_id = int(form.get("student_id") or 0)
        except ValueError:
            lesson_id = student_id = 0

        if lesson_id:
            db = get_db()
            db.execute("DELETE FROM schedule WHERE id = ?", (lesson_id,))
            db.commit()
            db.close()
            self.flash("info", "Урок удалён.")

        if student_id:
            return self.redirect(f"/schedule?student={student_id}")
        self.redirect("/schedule")

    def page_grades(self):
        if not self.require_login():
            return

        form = self._read_form() if self.command == "POST" else {}
        student, can_edit = self._resolve_target_student(form)
        if student is None:
            return

        target_id = student["id"]
        db = get_db()

        if self.command == "POST":
            if not can_edit:
                db.close()
                self.flash("error", "Ученик не может ставить оценки.")
                return self.redirect("/grades")

            subject = (form.get("subject") or "").strip()
            date_str = (form.get("date") or "").strip()
            comment = (form.get("comment") or "").strip()
            try:
                grade = int(form.get("grade") or 0)
            except ValueError:
                grade = 0

            if not subject:
                self.flash("error", "Укажите предмет.")
            elif grade not in (2, 3, 4, 5):
                self.flash("error", "Оценка должна быть от 2 до 5.")
            else:
                try:
                    datetime.strptime(date_str, "%Y-%m-%d")
                except ValueError:
                    date_str = date.today().isoformat()
                db.execute(
                    "INSERT INTO grades "
                    "(user_id, subject, grade, date, comment) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (target_id, subject, grade, date_str, comment or None),
                )
                db.commit()
                self.flash("success", "Оценка добавлена.")
            db.close()
            return self.redirect(f"/grades?student={target_id}")

        rows = db.execute(
            "SELECT * FROM grades WHERE user_id = ? "
            "ORDER BY date DESC, id DESC",
            (target_id,),
        ).fetchall()

        stats = db.execute(
            "SELECT AVG(grade) AS avg_grade, COUNT(*) AS total "
            "FROM grades WHERE user_id = ?",
            (target_id,),
        ).fetchone()
        db.close()

        avg = round(stats["avg_grade"], 2) if stats["avg_grade"] else "—"

        if rows:
            body = ("<table><thead><tr>"
                    "<th>Дата</th><th>Предмет</th><th>Оценка</th>"
                    "<th>Комментарий</th>")
            if can_edit:
                body += "<th></th>"
            body += "</tr></thead><tbody>"
            for g in rows:
                body += (
                    f"<tr><td>{esc(g['date'])}</td>"
                    f"<td><strong>{esc(g['subject'])}</strong></td>"
                    f'<td><span class="grade grade--{g["grade"]}">'
                    f'{g["grade"]}</span></td>'
                    f'<td class="muted">{esc(g["comment"]) or "—"}</td>'
                )
                if can_edit:
                    body += (
                        f'<td><form method="post" action="/grades/delete" '
                        f'class="inline js-confirm">'
                        f'<input type="hidden" name="id" value="{g["id"]}">'
                        f'<input type="hidden" name="student_id" '
                        f'value="{target_id}">'
                        f'<button class="btn btn--danger btn--small" '
                        f'type="submit">✕</button></form></td>'
                    )
                body += "</tr>"
            body += "</tbody></table>"
        else:
            body = '<p class="muted">Записей нет.</p>'

        if can_edit:
            add_section = (
                '<section class="card">'
                '<h2>Поставить оценку</h2>'
                '<form method="post" action="/grades" class="form form--grid">'
                f'<input type="hidden" name="student_id" value="{target_id}">'
                '<label>Предмет'
                '<input type="text" name="subject" maxlength="60" required>'
                '</label>'
                '<label>Оценка'
                '<select name="grade" required>'
                '<option value="5">5</option>'
                '<option value="4">4</option>'
                '<option value="3">3</option>'
                '<option value="2">2</option>'
                '</select></label>'
                '<label>Дата'
                f'<input type="date" name="date" '
                f'value="{date.today().isoformat()}" required></label>'
                '<label>Комментарий'
                '<input type="text" name="comment" maxlength="80" '
                'placeholder="Контрольная, ответ у доски..."></label>'
                '<button class="btn" type="submit">Добавить</button>'
                '</form></section>'
            )
            title_suffix = f'ученика: {esc(student["username"])}'
            back_link = ('<p class="muted">'
                         '<a href="/">← Назад к списку учеников</a></p>')
        else:
            add_section = ""
            title_suffix = ""
            back_link = ""

        html = self._render_page(
            "Оценки · Дневник",
            "grades.html",
            title_suffix=title_suffix,
            back_link=back_link,
            avg=avg,
            total=stats["total"],
            add_section=add_section,
            grades_table=body,
        )
        self._send_html(200, html)

    def page_grades_delete(self):
        if not self.require_login():
            return
        if not self.is_teacher():
            self.flash("error", "Ученик не может менять оценки.")
            return self.redirect("/grades")

        form = self._read_form()
        try:
            grade_id = int(form.get("id") or 0)
            student_id = int(form.get("student_id") or 0)
        except ValueError:
            grade_id = student_id = 0

        if grade_id:
            db = get_db()
            db.execute("DELETE FROM grades WHERE id = ?", (grade_id,))
            db.commit()
            db.close()
            self.flash("info", "Оценка удалена.")

        if student_id:
            return self.redirect(f"/grades?student={student_id}")
        self.redirect("/grades")


def main():
    os.makedirs(TEMPLATES_DIR, exist_ok=True)
    os.makedirs(STATIC_DIR, exist_ok=True)
    init_db()
    server = ThreadingHTTPServer((HOST, PORT), DiaryHandler)
    print(f"Сервер запущен: http://{HOST}:{PORT}")
    print("Остановка: Ctrl+C")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nОстановлено.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
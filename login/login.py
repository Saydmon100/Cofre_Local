import json
import os
import re
import time
import base64
import hmac
import hashlib
import secrets
import tkinter as tk
from tkinter import ttk, messagebox

APP_NAME = "CofreLocal"
USERS_FILE = "users.json"
SETTINGS_FILE = "settings.json"

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

# Segurança (percepção + prática local):
# PBKDF2 é uma opção aceitável quando Argon2/bcrypt não estão disponíveis nativamente.
# (Você pode citar OWASP no README para justificar.)  :contentReference[oaicite:4]{index=4}
PBKDF2_ITERATIONS = 200_000
SALT_BYTES = 16
DKLEN = 32


def pbkdf2_hash_password(password: str, salt_b64: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    salt = base64.b64decode(salt_b64.encode("utf-8"))
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=DKLEN)
    return base64.b64encode(dk).decode("utf-8")


def new_salt_b64() -> str:
    return base64.b64encode(secrets.token_bytes(SALT_BYTES)).decode("utf-8")


def load_json(path: str, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path: str, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


class UserStore:
    def __init__(self, path=USERS_FILE):
        self.path = path
        self.data = load_json(self.path, {"users": []})

    def save(self):
        save_json(self.path, self.data)

    def find_by_email(self, email: str):
        email_l = email.strip().lower()
        for u in self.data["users"]:
            if u["email"].lower() == email_l:
                return u
        return None

    def add_user(self, name: str, email: str, password: str):
        if self.find_by_email(email):
            raise ValueError("Este email já está cadastrado.")
        salt = new_salt_b64()
        pwd_hash = pbkdf2_hash_password(password, salt, PBKDF2_ITERATIONS)
        user = {
            "name": name.strip(),
            "email": email.strip(),
            "salt": salt,
            "hash": pwd_hash,
            "iterations": PBKDF2_ITERATIONS,
            "created_at": int(time.time())
        }
        self.data["users"].append(user)
        self.save()
        return user

    def verify_login(self, email: str, password: str) -> bool:
        u = self.find_by_email(email)
        if not u:
            return False
        computed = pbkdf2_hash_password(password, u["salt"], int(u.get("iterations", PBKDF2_ITERATIONS)))
        # comparação constante
        return hmac.compare_digest(computed, u["hash"])


class RegisterDialog(tk.Toplevel):
    def __init__(self, parent, store: UserStore):
        super().__init__(parent)
        self.title("Criar conta")
        self.resizable(False, False)
        self.store = store
        self.result_email = None

        self.columnconfigure(0, weight=1)

        frm = ttk.Frame(self, padding=16)
        frm.grid(row=0, column=0, sticky="nsew")

        ttk.Label(frm, text="Criar conta no CofreLocal", font=("Segoe UI", 12, "bold")).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))

        ttk.Label(frm, text="Nome").grid(row=1, column=0, sticky="w")
        self.name_var = tk.StringVar()
        self.name_ent = ttk.Entry(frm, textvariable=self.name_var, width=34)
        self.name_ent.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(0, 8))

        ttk.Label(frm, text="Email").grid(row=3, column=0, sticky="w")
        self.email_var = tk.StringVar()
        self.email_ent = ttk.Entry(frm, textvariable=self.email_var, width=34)
        self.email_ent.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(0, 8))

        ttk.Label(frm, text="Senha").grid(row=5, column=0, sticky="w")
        self.pwd_var = tk.StringVar()
        self.pwd_ent = ttk.Entry(frm, textvariable=self.pwd_var, show="•", width=34)
        self.pwd_ent.grid(row=6, column=0, sticky="ew", pady=(0, 4))

        self.show_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frm, text="Mostrar senha", variable=self.show_var, command=self._toggle_show).grid(row=6, column=1, sticky="w", padx=(10, 0))

        self.str_var = tk.StringVar(value="Força da senha: —")
        ttk.Label(frm, textvariable=self.str_var).grid(row=7, column=0, columnspan=2, sticky="w", pady=(0, 8))

        self.hint_var = tk.StringVar(value="Dica: use 8+ caracteres, letras e números.")
        ttk.Label(frm, textvariable=self.hint_var, foreground="#555").grid(row=8, column=0, columnspan=2, sticky="w", pady=(0, 12))

        self.msg_var = tk.StringVar(value="")
        ttk.Label(frm, textvariable=self.msg_var, foreground="#b00020").grid(row=9, column=0, columnspan=2, sticky="w")

        btns = ttk.Frame(frm)
        btns.grid(row=10, column=0, columnspan=2, sticky="ew", pady=(12, 0))
        btns.columnconfigure(0, weight=1)
        btns.columnconfigure(1, weight=1)

        ttk.Button(btns, text="Cancelar", command=self.destroy).grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ttk.Button(btns, text="Criar conta", command=self._submit).grid(row=0, column=1, sticky="ew", padx=(6, 0))

        self.pwd_ent.bind("<KeyRelease>", lambda e: self._update_strength())
        self._update_strength()

        self.name_ent.focus_set()
        self.grab_set()

    def _toggle_show(self):
        self.pwd_ent.configure(show="" if self.show_var.get() else "•")

    def _password_strength(self, pwd: str) -> int:
        score = 0
        if len(pwd) >= 8: score += 1
        if re.search(r"[A-Z]", pwd): score += 1
        if re.search(r"[a-z]", pwd): score += 1
        if re.search(r"\d", pwd): score += 1
        if re.search(r"[^A-Za-z0-9]", pwd): score += 1
        return score

    def _update_strength(self):
        pwd = self.pwd_var.get()
        score = self._password_strength(pwd)
        labels = ["muito fraca", "fraca", "ok", "boa", "forte", "muito forte"]
        self.str_var.set(f"Força da senha: {labels[score]}")

    def _submit(self):
        name = self.name_var.get().strip()
        email = self.email_var.get().strip()
        pwd = self.pwd_var.get()

        if not name:
            self.msg_var.set("Informe seu nome.")
            self.name_ent.focus_set()
            return
        if not email or not EMAIL_RE.match(email):
            self.msg_var.set("Informe um email válido.")
            self.email_ent.focus_set()
            return
        if len(pwd) < 8 or not re.search(r"[A-Za-z]", pwd) or not re.search(r"\d", pwd):
            self.msg_var.set("Senha inválida. Use 8+ caracteres e inclua letras e números.")
            self.pwd_ent.focus_set()
            return

        try:
            self.store.add_user(name, email, pwd)
            self.result_email = email
            messagebox.showinfo("Conta criada", "Conta criada com sucesso! Agora faça login.")
            self.destroy()
        except ValueError as e:
            self.msg_var.set(str(e))


class App(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=18)
        self.master = master
        self.store = UserStore()
        self.settings = load_json(SETTINGS_FILE, {"last_email": ""})

        self.failed_attempts = 0
        self.locked_until = 0

        self._build_ui()

    def _build_ui(self):
        self.master.title(f"{APP_NAME} — Login Offline")
        self.master.resizable(False, False)

        style = ttk.Style()
        # Tenta um tema mais “limpo” (varia por SO)
        for theme in ("clam", "vista", "xpnative", "alt", "default"):
            try:
                style.theme_use(theme)
                break
            except tk.TclError:
                pass

        self.grid(row=0, column=0, sticky="nsew")
        self.columnconfigure(0, weight=1)

        title = ttk.Label(self, text="🔒 CofreLocal", font=("Segoe UI", 16, "bold"))
        title.grid(row=0, column=0, sticky="w")

        subtitle = ttk.Label(self, text="Acesse seu cofre local com segurança (offline).", foreground="#555")
        subtitle.grid(row=1, column=0, sticky="w", pady=(0, 12))

        form = ttk.Frame(self)
        form.grid(row=2, column=0, sticky="ew")
        form.columnconfigure(0, weight=1)

        ttk.Label(form, text="Email").grid(row=0, column=0, sticky="w")
        self.email_var = tk.StringVar(value=self.settings.get("last_email", ""))
        self.email_ent = ttk.Entry(form, textvariable=self.email_var, width=40)
        self.email_ent.grid(row=1, column=0, sticky="ew", pady=(0, 10))

        ttk.Label(form, text="Senha").grid(row=2, column=0, sticky="w")
        self.pwd_var = tk.StringVar()
        self.pwd_ent = ttk.Entry(form, textvariable=self.pwd_var, show="•", width=40)
        self.pwd_ent.grid(row=3, column=0, sticky="ew", pady=(0, 6))

        opts = ttk.Frame(form)
        opts.grid(row=4, column=0, sticky="ew", pady=(0, 10))
        opts.columnconfigure(0, weight=1)

        self.show_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="Mostrar senha", variable=self.show_var, command=self._toggle_show).grid(row=0, column=0, sticky="w")

        self.remember_var = tk.BooleanVar(value=True if self.email_var.get() else False)
        ttk.Checkbutton(opts, text="Lembrar meu email", variable=self.remember_var).grid(row=0, column=1, sticky="e")

        self.status_var = tk.StringVar(value="Digite seu email e senha.")
        self.status_lbl = ttk.Label(form, textvariable=self.status_var, foreground="#333")
        self.status_lbl.grid(row=5, column=0, sticky="w")

        self.lock_var = tk.StringVar(value="")
        self.lock_lbl = ttk.Label(form, textvariable=self.lock_var, foreground="#b00020")
        self.lock_lbl.grid(row=6, column=0, sticky="w", pady=(4, 0))

        btns = ttk.Frame(self)
        btns.grid(row=3, column=0, sticky="ew", pady=(14, 0))
        btns.columnconfigure(0, weight=1)
        btns.columnconfigure(1, weight=1)

        self.login_btn = ttk.Button(btns, text="Entrar", command=self.on_login)
        self.login_btn.grid(row=0, column=0, sticky="ew", padx=(0, 6))

        ttk.Button(btns, text="Criar conta", command=self.on_register).grid(row=0, column=1, sticky="ew", padx=(6, 0))

        help_row = ttk.Frame(self)
        help_row.grid(row=4, column=0, sticky="ew", pady=(10, 0))
        help_row.columnconfigure(0, weight=1)

        ttk.Button(help_row, text="Como funciona?", command=self.on_help).grid(row=0, column=0, sticky="w")

        foot = ttk.Label(self, text="Dado importante: a senha não é salva em texto puro (apenas hash).", foreground="#555")
        foot.grid(row=5, column=0, sticky="w", pady=(10, 0))

        # Atalhos de teclado (eficiência)
        self.master.bind("<Return>", lambda e: self.on_login())
        self.email_ent.focus_set()

        # Atualiza estado do botão conforme preenchimento (prevenção de erro)
        self.email_ent.bind("<KeyRelease>", lambda e: self._update_login_state())
        self.pwd_ent.bind("<KeyRelease>", lambda e: self._update_login_state())
        self._update_login_state()

    def _toggle_show(self):
        self.pwd_ent.configure(show="" if self.show_var.get() else "•")

    def _update_login_state(self):
        locked = time.time() < self.locked_until
        has_data = bool(self.email_var.get().strip()) and bool(self.pwd_var.get())
        self.login_btn.configure(state=("disabled" if locked or not has_data else "normal"))

    def _set_status(self, text, error=False):
        self.status_var.set(text)
        self.status_lbl.configure(foreground=("#b00020" if error else "#333"))

    def _lock_for(self, seconds: int):
        self.locked_until = time.time() + seconds
        self._tick_lock()

    def _tick_lock(self):
        remaining = int(self.locked_until - time.time())
        if remaining > 0:
            self.lock_var.set(f"Muitas tentativas. Tente novamente em {remaining}s.")
            self._update_login_state()
            self.after(200, self._tick_lock)
        else:
            self.lock_var.set("")
            self.failed_attempts = 0
            self._update_login_state()

    def on_help(self):
        messagebox.showinfo(
            "Como funciona?",
            "• Funciona offline.\n"
            "• Os usuários ficam em users.json.\n"
            "• A senha não é salva em texto puro.\n\n"
            "Dicas:\n"
            "1) Use seu email cadastrado.\n"
            "2) Se errar a senha muitas vezes, o sistema bloqueia por alguns segundos."
        )

    def on_register(self):
        dlg = RegisterDialog(self.master, self.store)
        self.master.wait_window(dlg)
        if dlg.result_email:
            self.email_var.set(dlg.result_email)
            self.pwd_var.set("")
            self._set_status("Conta criada! Agora entre com sua senha.")
            self._update_login_state()
            self.pwd_ent.focus_set()

    def on_login(self):
        if time.time() < self.locked_until:
            self._update_login_state()
            return

        email = self.email_var.get().strip()
        pwd = self.pwd_var.get()

        if not email or not EMAIL_RE.match(email):
            self._set_status("Informe um email válido.", error=True)
            self.email_ent.focus_set()
            return
        if not pwd:
            self._set_status("Informe sua senha.", error=True)
            self.pwd_ent.focus_set()
            return

        # Feedback de status (visibilidade do sistema)  :contentReference[oaicite:5]{index=5}
        self._set_status("Verificando…")
        self.login_btn.configure(state="disabled")
        self.master.after(600, lambda: self._finish_login(email, pwd))

    def _finish_login(self, email, pwd):
        ok = self.store.verify_login(email, pwd)

        if ok:
            if self.remember_var.get():
                self.settings["last_email"] = email
                save_json(SETTINGS_FILE, self.settings)

            user = self.store.find_by_email(email)
            name = user.get("name", "usuário")
            self._set_status(f"✅ Bem-vindo, {name}! Login realizado com sucesso.")
            messagebox.showinfo("Sucesso", f"Login OK!\n\nOlá, {name}.\n(Aqui você poderia abrir o 'cofre' na mesma janela.)")
            self.pwd_var.set("")
        else:
            self.failed_attempts += 1
            self._set_status("Email ou senha incorretos. Verifique e tente novamente.", error=True)

            # Bloqueio leve para percepção de segurança
            if self.failed_attempts >= 3:
                self._lock_for(15)

        self._update_login_state()


def ensure_files_exist():
    if not os.path.exists(USERS_FILE):
        save_json(USERS_FILE, {"users": []})
    if not os.path.exists(SETTINGS_FILE):
        save_json(SETTINGS_FILE, {"last_email": ""})


def main():
    ensure_files_exist()
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()

import os
from typing import Optional, Tuple, List

from dotenv import load_dotenv
from flask import (
    Flask, jsonify, request, render_template, redirect, url_for, flash
)

import bcrypt
import psycopg
from psycopg.rows import dict_row

# Tenta usar pool de conexões; se não houver, usa conexão direta
try:
    from psycopg_pool import ConnectionPool  # type: ignore
    HAS_POOL = True
except Exception:
    HAS_POOL = False

# ----------------------------
# Configuração
# ----------------------------
load_dotenv()
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:1234@localhost:5432/web1"  # fallback para aula
)

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", "dev-secret")  # usada pelo flash
app.config["TEMPLATES_AUTO_RELOAD"] = True

# ----------------------------
# Conexão com banco
# ----------------------------
if HAS_POOL:
    pool = ConnectionPool(
        conninfo=DATABASE_URL,
        min_size=1,
        max_size=5,
        timeout=10,
        kwargs={"autocommit": False},  # transações explícitas
    )

    def _conn():
        return pool.connection()
else:
    def _conn():
        # Conexão direta (sem pool)
        return psycopg.connect(DATABASE_URL, row_factory=dict_row)

def db_query(sql: str, params: Optional[Tuple] = None) -> List[dict]:
    """Consulta de leitura -> lista de dicts."""
    with _conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql, params or ())
            return cur.fetchall()

def db_execute(sql: str, params: Optional[Tuple] = None, returning: bool = False):
    """Escrita (INSERT/UPDATE/DELETE). Se returning=True, retorna rows."""
    with _conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql, params or ())
            rows = cur.fetchall() if returning else None
        conn.commit()
    return rows

# ----------------------------
# Utilidades
# ----------------------------
def hash_password(plain: str) -> str:
    """Gera hash bcrypt (string ASCII)."""
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

# ----------------------------
# Rotas básicas
# ----------------------------
@app.get("/")
def index():
    # manda direto para a lista HTML
    return redirect(url_for("users_page"))

@app.get("/health")
def health():
    try:
        one = db_query("SELECT 1 AS ok;")[0]["ok"]
        return jsonify({"status": "ok", "db": one, "pool": HAS_POOL}), 200
    except Exception as e:
        return jsonify({"status": "error", "detail": str(e)}), 500

@app.get("/db/version")
def db_version():
    try:
        v = db_query("SELECT version();")[0]["version"]
        return jsonify({"version": v}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ----------------------------
# API JSON (ex.: para testes via curl/Insomnia)
# ----------------------------
@app.get("/users")
def list_users_api():
    try:
        rows = db_query("SELECT id, nome, email FROM public.usuarios ORDER BY id ASC;")
        return jsonify({"data": rows}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/users")
def create_user_api():
    try:
        payload = request.get_json(silent=True) or {}
        nome = payload.get("nome")
        email = payload.get("email")
        senha = payload.get("senha")

        if not all([nome, email, senha]):
            return jsonify({"error": "nome, email e senha são obrigatórios"}), 400

        senha_hash = hash_password(senha)

        row = db_execute(
            """
            INSERT INTO public.usuarios (nome, email, senha)
            VALUES (%s, %s, %s)
            RETURNING id, nome, email;
            """,
            (nome, email, senha_hash),
            returning=True,
        )
        return jsonify({"data": row[0]}), 201
    except psycopg.errors.UniqueViolation:
        return jsonify({"error": "email já cadastrado"}), 409
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ----------------------------
# Páginas HTML (form + lista + editar + excluir)
# ----------------------------
@app.get("/users/new")
def users_new_form():
    """Formulário HTML de cadastro."""
    return render_template("users_new.html")

@app.post("/users/form")
def users_create_from_form():
    """Recebe POST do <form> e insere no banco."""
    try:
        nome = (request.form.get("nome") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        senha = request.form.get("senha") or ""

        if not nome or not email or not senha:
            flash("Preencha nome, email e senha.", "error")
            return redirect(url_for("users_new_form"))

        senha_hash = hash_password(senha)

        db_execute(
            """
            INSERT INTO public.usuarios (nome, email, senha)
            VALUES (%s, %s, %s)
            RETURNING id;
            """,
            (nome, email, senha_hash),
            returning=True,
        )
        flash("Usuário criado com sucesso!", "success")
        return redirect(url_for("users_page"))

    except psycopg.errors.UniqueViolation:
        flash("Email já cadastrado.", "error")
        return redirect(url_for("users_new_form"))
    except Exception as e:
        flash(f"Erro: {e}", "error")
        return redirect(url_for("users_new_form"))

@app.get("/users/page")
def users_page():
    """Lista usuários em HTML com busca (?q=...)."""
    q = (request.args.get("q") or "").strip()
    if q:
        like = f"%{q}%"
        rows = db_query(
            """
            SELECT id, nome, email
              FROM public.usuarios
             WHERE nome ILIKE %s OR email ILIKE %s
             ORDER BY id ASC;
            """,
            (like, like),
        )
    else:
        rows = db_query(
            "SELECT id, nome, email FROM public.usuarios ORDER BY id ASC;"
        )
    return render_template("users_page.html", users=rows, q=q)

@app.get("/users/<int:user_id>/edit")
def users_edit_form(user_id: int):
    """Formulário HTML de edição."""
    rows = db_query(
        "SELECT id, nome, email FROM public.usuarios WHERE id = %s;",
        (user_id,),
    )
    if not rows:
        flash("Usuário não encontrado.", "error")
        return redirect(url_for("users_page"))
    return render_template("users_edit.html", u=rows[0])

@app.post("/users/<int:user_id>/edit")
def users_edit_post(user_id: int):
    """Recebe POST do form de edição e atualiza o registro."""
    try:
        nome = (request.form.get("nome") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        senha = request.form.get("senha") or ""  # opcional

        if not nome or not email:
            flash("Nome e email são obrigatórios.", "error")
            return redirect(url_for("users_edit_form", user_id=user_id))

        sets, params = [], []
        sets.append("nome = %s");  params.append(nome)
        sets.append("email = %s"); params.append(email)
        if senha:
            sets.append("senha = %s"); params.append(hash_password(senha))
        params.append(user_id)

        sql = f"""
            UPDATE public.usuarios
               SET {', '.join(sets)}
             WHERE id = %s
         RETURNING id;
        """
        rows = db_execute(sql, tuple(params), returning=True)
        if not rows:
            flash("Usuário não encontrado.", "error")
            return redirect(url_for("users_page"))

        flash("Usuário atualizado com sucesso!", "success")
        return redirect(url_for("users_page"))

    except psycopg.errors.UniqueViolation:
        flash("Email já cadastrado por outro usuário.", "error")
        return redirect(url_for("users_edit_form", user_id=user_id))
    except Exception as e:
        flash(f"Erro ao atualizar: {e}", "error")
        return redirect(url_for("users_edit_form", user_id=user_id))

@app.post("/users/<int:user_id>/delete")
def users_delete(user_id: int):
    """Exclui um usuário e volta para a lista."""
    try:
        rows = db_execute(
            "DELETE FROM public.usuarios WHERE id = %s RETURNING id;",
            (user_id,),
            returning=True
        )
        if not rows:
            flash("Usuário não encontrado.", "error")
        else:
            flash(f"Usuário {rows[0]['id']} removido.", "success")
        return redirect(url_for("users_page"))
    except Exception as e:
        flash(f"Erro ao excluir: {e}", "error")
        return redirect(url_for("users_page"))

# ----------------------------
# Main
# ----------------------------
if __name__ == "__main__":
    # Em produção, use gunicorn/uvicorn; aqui é só para desenvolvimento
    app.run(host="0.0.0.0", port=5000, debug=True)

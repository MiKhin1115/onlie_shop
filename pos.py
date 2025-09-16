"""
Streamlit Inventory Management App
----------------------------------
A compact, single-file Streamlit app that mirrors classic PHP CRUD inventory systems
(products, categories, users, sales, reports) using a local SQLite database.

⚠️ Notes
- Uses Argon2id for password hashing (via argon2-cffi). Do NOT store plain passwords.
- Run: `pip install streamlit pandas sqlalchemy python-dateutil pillow argon2-cffi`
       then `streamlit run app.py`.
- The app creates an `inventory.db` SQLite file and an `uploads/` folder next to this script.
- An initial admin account is created on first run: username `admin`, password `admin` (please change it!).

Tested with Streamlit 1.35+.
"""

import os
import io
import hashlib
import secrets
from datetime import datetime, date
from dateutil.relativedelta import relativedelta
from typing import Optional, Tuple

import pandas as pd
import streamlit as st
from sqlalchemy import (
    create_engine, Column, Integer, String, Float, Boolean, DateTime, ForeignKey, func
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship, scoped_session
from PIL import Image, UnidentifiedImageError

# --- Password hashing with Argon2id ---
from argon2 import PasswordHasher, exceptions as argon2_exc

_ph = PasswordHasher()  # good defaults


def hash_password(password: str) -> str:
    """Return Argon2id hash with a prefix so the scheme is explicit."""
    return "argon2:" + _ph.hash(password)


def verify_password(plain: str, stored: str) -> tuple[bool, str | None]:
    """
    Verify an Argon2id hash. Returns (ok, upgraded_hash_or_None).
    If Argon2 parameters are outdated, returns a new hash for transparent upgrade.
    """
    if not stored or not stored.startswith("argon2:"):
        return False, None
    h = stored.split(":", 1)[1]
    try:
        ok = _ph.verify(h, plain)
        if ok and _ph.check_needs_rehash(h):
            return True, hash_password(plain)
        return True, None
    except argon2_exc.VerifyMismatchError:
        return False, None


# -----------------------------
# App Setup & Configuration
# -----------------------------
APP_TITLE = "စျေးဆိုင်"
DB_PATH = "inventory.db"
UPLOAD_DIR = "uploads"

st.set_page_config(page_title=APP_TITLE, page_icon="🛒", layout="wide")

os.makedirs(UPLOAD_DIR, exist_ok=True)

engine = create_engine(
    f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = scoped_session(sessionmaker(
    bind=engine, autoflush=False, autocommit=False, future=True))
Base = declarative_base()


# -----------------------------
# Database Models
# -----------------------------
class SessionToken(Base):
    __tablename__ = "session_tokens"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"),
                     index=True, nullable=False)
    token_hash = Column(String, unique=True, index=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("User")


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    # Optional avatar storage (uncomment if you add it to your DB)
    # avatar_url = Column(String, nullable=True)

    sales = relationship("Sale", back_populates="sold_by_user")


class Category(Base):
    __tablename__ = "categories"
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    products = relationship("Product", back_populates="category")


class Product(Base):
    __tablename__ = "products"
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    category_id = Column(Integer, ForeignKey("categories.id"), nullable=True)
    quantity = Column(Integer, default=0)
    cost_price = Column(Float, default=0.0)
    sale_price = Column(Float, default=0.0)
    image_path = Column(String, nullable=True)

    category = relationship("Category", back_populates="products")
    sales = relationship("Sale", back_populates="product")


class Sale(Base):
    __tablename__ = "sales"
    id = Column(Integer, primary_key=True)
    product_id = Column(Integer, ForeignKey("products.id"))
    quantity = Column(Integer, default=1)
    price_at_sale = Column(Float, default=0.0)
    sale_date = Column(DateTime, default=datetime.utcnow)
    sold_by = Column(Integer, ForeignKey("users.id"), nullable=True)

    product = relationship("Product", back_populates="sales")
    sold_by_user = relationship("User", back_populates="sales")


# -----------------------------
# Helpers (DB + session tokens)
# -----------------------------
def init_db():
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        # Seed admin user if empty (Argon2id)
        if not db.query(User).first():
            admin = User(username="admin", password_hash=hash_password(
                "admin"), is_admin=True)
            db.add(admin)
            db.commit()
        # Seed a default category
        if not db.query(Category).first():
            db.add(Category(name="Uncategorized"))
            db.commit()


def get_db():
    return SessionLocal()


# Persistent login helpers (token in URL)
TOKEN_PARAM = "t"  # query param name


def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _set_url_token(raw_token: str | None):
    try:
        # type: ignore[attr-defined]
        st.query_params[TOKEN_PARAM] = raw_token if raw_token else None
    except Exception:
        if raw_token:
            st.experimental_set_query_params(**{TOKEN_PARAM: raw_token})
        else:
            st.experimental_set_query_params()


def _get_url_token() -> str | None:
    try:
        v = st.query_params.get(TOKEN_PARAM)  # type: ignore[attr-defined]
        return v if isinstance(v, str) else None
    except Exception:
        params = st.experimental_get_query_params()
        arr = params.get(TOKEN_PARAM)
        return arr[0] if arr else None


def issue_persistent_token(db, user_id: int, days: int = 30) -> str:
    raw = secrets.token_urlsafe(32)
    rec = SessionToken(
        user_id=user_id,
        token_hash=_hash_token(raw),
        expires_at=datetime.utcnow() + relativedelta(days=days),
    )
    db.add(rec)
    db.commit()
    return raw


def restore_session_from_token() -> bool:
    raw = _get_url_token()
    if not raw:
        return False
    with get_db() as db:
        now = datetime.utcnow()
        th = _hash_token(raw)
        rec = db.query(SessionToken).filter(
            SessionToken.token_hash == th).first()
        if not rec or rec.expires_at <= now:
            if rec:
                db.delete(rec)
                db.commit()
            _set_url_token(None)
            return False
        u = db.get(User, rec.user_id)
        if not u:
            db.delete(rec)
            db.commit()
            _set_url_token(None)
            return False
        st.session_state.user = {
            "id": u.id, "username": u.username, "is_admin": u.is_admin}
        st.session_state.persistent_token_hash = th
        return True


def revoke_current_token():
    raw = _get_url_token()
    th = st.session_state.get("persistent_token_hash")
    with get_db() as db:
        q = db.query(SessionToken)
        if th:
            q = q.filter(SessionToken.token_hash == th)
        elif raw:
            q = q.filter(SessionToken.token_hash == _hash_token(raw))
        else:
            q = None
        if q is not None:
            rec = q.first()
            if rec:
                db.delete(rec)
                db.commit()
    _set_url_token(None)
    st.session_state.pop("persistent_token_hash", None)


# -----------------------------
# Auth UI
# -----------------------------
def login_view():
    st.title("🔐 Sign in")
    with st.form("login_form", clear_on_submit=False):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        remember = st.checkbox("Remember me for 30 days", value=True)
        submitted = st.form_submit_button("Sign in")
    if submitted:
        with get_db() as db:
            user = db.query(User).filter(User.username == username).first()
            if user:
                ok, upgraded = verify_password(password, user.password_hash)
                if ok:
                    if upgraded:
                        user.password_hash = upgraded
                        db.commit()
                    st.session_state.user = {
                        "id": user.id, "username": user.username, "is_admin": user.is_admin
                    }
                    if remember:
                        raw = issue_persistent_token(db, user.id, days=30)
                        st.session_state.persistent_token_hash = _hash_token(
                            raw)
                        _set_url_token(raw)  # survive reload/new tabs
                    st.success("Logged in!")
                    st.rerun()
            st.error("Invalid username or password.")


# -----------------------------
# Topbar & Navigation
# -----------------------------
def _render_avatar(src: str | None, username: str, size: int = 40):
    if src and isinstance(src, str):
        if src.startswith("http"):
            st.image(src, width=size)
            return
        if os.path.exists(src):
            with open(src, "rb") as f:
                st.image(f.read(), width=size)
                return
    st.image(
        f"https://ui-avatars.com/api/?name={username}&size={size*2}&background=random", width=size)


def topbar():
    user_state = st.session_state.get("user")
    cols = st.columns([6, 3, 1])
    with cols[0]:
        st.markdown(f"### 📦 {APP_TITLE}")
    with cols[1]:
        if user_state:
            # If you add avatar_url to the model, this will display it.
            with get_db() as db:
                u = db.get(User, user_state["id"])
                avatar = getattr(u, "avatar_url", None) if u else None
            a, b = st.columns([1, 4])
            with a:
                _render_avatar(avatar, user_state["username"], size=40)
            with b:
                st.caption(
                    f"**{user_state['username']}** {'(admin)' if user_state['is_admin'] else ''}")
    with cols[2]:
        if st.button("Logout", use_container_width=True):
            revoke_current_token()
            st.session_state.user = None
            st.rerun()


def sidebar_nav() -> str:
    user = st.session_state.get("user")
    st.sidebar.header("Navigation")
    pages = ["Dashboard", "Products", "Categories", "Sales", "Reports"]
    if user and user.get("is_admin"):
        pages.append("Users")
    pages.append("Settings")
    return st.sidebar.radio("", pages, index=0)


# -----------------------------
# Pages
# -----------------------------
def page_dashboard():
    with get_db() as db:
        # KPIs
        prod_count = db.query(func.count(Product.id)).scalar() or 0
        cat_count = db.query(func.count(Category.id)).scalar() or 0
        user_count = db.query(func.count(User.id)).scalar() or 0
        total_qty = db.query(func.coalesce(
            func.sum(Product.quantity), 0)).scalar()

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Products", prod_count)
        c2.metric("Categories", cat_count)
        c3.metric("Users", user_count)
        c4.metric("Total Stock Units", int(total_qty))

        # Sales (customizable)
        st.subheader("Sales (choose period)")
        mode = st.radio(
            "Range", ["Last N days", "Custom range"], horizontal=True)
        now = datetime.utcnow()
        if mode == "Last N days":
            n_days = st.number_input(
                "Days", min_value=1, max_value=365, value=30, step=1)
            start_dt, end_dt = now - relativedelta(days=int(n_days)), now
        else:
            cA, cB = st.columns(2)
            start_d = cA.date_input(
                "Start date", value=date.today() - relativedelta(days=30))
            end_d = cB.date_input("End date",   value=date.today())
            start_dt = datetime.combine(start_d, datetime.min.time())
            end_dt = datetime.combine(
                end_d,   datetime.min.time()) + relativedelta(days=1)

        sales_q = (
            db.query(Sale.sale_date.label("date"),
                     Sale.quantity, Sale.price_at_sale)
            .filter(Sale.sale_date >= start_dt, Sale.sale_date < end_dt)
            .all()
        )
        sales_df = pd.DataFrame([{"date": s.date.date(
        ), "units": s.quantity, "revenue": s.quantity * s.price_at_sale} for s in sales_q])

        if not sales_df.empty:
            kc1, kc2 = st.columns(2)
            kc1.metric("Units sold", int(sales_df["units"].sum()))
            kc2.metric("Revenue", f"{float(sales_df['revenue'].sum()):,.2f}")
            daily = (sales_df.groupby("date", as_index=False).agg(
                {"units": "sum", "revenue": "sum"}).sort_values("date"))
            st.bar_chart(daily.set_index("date")["units"], height=220)
        else:
            shown_start = start_dt.date().isoformat()
            shown_end = (end_dt - relativedelta(days=1)).date().isoformat()
            st.info(f"No sales between {shown_start} and {shown_end}.")

        # Low stock
        st.subheader("Low Stock Alerts (≤ 5 units)")
        low = db.query(Product).filter(Product.quantity <=
                                       5).order_by(Product.quantity.asc()).all()
        if low:
            st.dataframe(pd.DataFrame([
                {"ID": p.id, "Name": p.name, "Qty": p.quantity,
                    "Category": p.category.name if p.category else None}
                for p in low
            ]), use_container_width=True, hide_index=True)
        else:
            st.success("All good! No low stock items.")


def page_categories():
    st.header("Categories")
    with get_db() as db:
        # Create
        with st.form("add_cat", clear_on_submit=True):
            name = st.text_input("New category name")
            submitted = st.form_submit_button("Add")
        if submitted and name.strip():
            if db.query(Category).filter(func.lower(Category.name) == name.lower()).first():
                st.warning("Category already exists.")
            else:
                db.add(Category(name=name.strip()))
                db.commit()
                st.success("Category added.")
                st.rerun()

        # List / Edit / Delete
        cats = db.query(Category).order_by(Category.name.asc()).all()
        df = pd.DataFrame(
            [{"ID": c.id, "Name": c.name, "Products": len(c.products)} for c in cats])
        st.dataframe(df, use_container_width=True, hide_index=True)

        st.subheader("Edit / Delete")
        sel = st.selectbox("Choose category", options=[(
            c.id, c.name) for c in cats], format_func=lambda x: x[1] if isinstance(x, tuple) else x)
        if sel:
            cat_id = sel[0]
            cat = db.get(Category, cat_id)
            new_name = st.text_input("New name", value=cat.name)
            c1, c2 = st.columns(2)
            if c1.button("Save changes"):
                cat.name = new_name.strip()
                db.commit()
                st.success("Updated.")
                st.rerun()
            if c2.button("Delete", type="primary"):
                if cat.products:
                    st.error("Cannot delete: category has products.")
                else:
                    db.delete(cat)
                    db.commit()
                    st.success("Deleted.")
                    st.rerun()


def page_products():
    st.header("Products")
    with get_db() as db:
        cats = db.query(Category).order_by(Category.name.asc()).all()
        cat_opts = [(c.id, c.name) for c in cats]

        with st.expander("➕ Add product", expanded=False):
            with st.form("add_prod", clear_on_submit=True):
                name = st.text_input("Name")
                category = st.selectbox(
                    "Category", options=cat_opts, format_func=lambda x: x[1]) if cat_opts else None
                qty = st.number_input("Quantity", min_value=0, value=0, step=1)
                cost = st.number_input(
                    "Cost price", min_value=0.0, value=0.0, step=0.1)
                price = st.number_input(
                    "Sale price", min_value=0.0, value=0.0, step=0.1)
                image = st.file_uploader("Image (optional)", type=[
                                         "png", "jpg", "jpeg"])
                submitted = st.form_submit_button("Create")
            if submitted:
                if not name.strip():
                    st.warning("Name is required.")
                elif db.query(Product).filter(func.lower(Product.name) == name.lower()).first():
                    st.warning("Product already exists.")
                else:
                    img_path = None
                    if image is not None:
                        ext = os.path.splitext(image.name)[1].lower()
                        safe_name = f"product_{int(datetime.utcnow().timestamp())}{ext}"
                        img_path = os.path.join(UPLOAD_DIR, safe_name)
                        with open(img_path, "wb") as f:
                            f.write(image.read())
                    prod = Product(
                        name=name.strip(),
                        category_id=category[0] if category else None,
                        quantity=int(qty), cost_price=float(cost), sale_price=float(price),
                        image_path=img_path
                    )
                    db.add(prod)
                    db.commit()
                    st.success("Product created.")
                    st.rerun()

        # Search & table (with photos)
        q = st.text_input("Search by name contains…")
        query = db.query(Product)
        if q:
            query = query.filter(Product.name.ilike(f"%{q}%"))
        prods = query.order_by(Product.name.asc()).all()

        rows = []
        for p in prods:
            photo = p.image_path if (p.image_path and os.path.exists(
                p.image_path)) else "https://placehold.co/60x60?text=No+Img"
            rows.append({
                "Photo": photo,
                "ID": p.id,
                "Name": p.name,
                "Category": p.category.name if p.category else None,
                "Qty": p.quantity,
                "Cost": p.cost_price,
                "Price": p.sale_price,
            })
        df = pd.DataFrame(rows)
        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Photo": st.column_config.ImageColumn("Photo", width="small"),
                "Qty":   st.column_config.NumberColumn("Qty", step=1),
                "Cost":  st.column_config.NumberColumn("Cost", format="%.2f"),
                "Price": st.column_config.NumberColumn("Price", format="%.2f"),
            },
        )

        st.subheader("Gallery")
        cols = st.columns(5)
        for i, p in enumerate(prods):
            with cols[i % 5]:
                img = p.image_path if (p.image_path and os.path.exists(
                    p.image_path)) else "https://placehold.co/200x150?text=No+Image"
                st.image(img, use_container_width=True)
                st.caption(
                    f"{p.name}\n\nStock: {p.quantity} · Price: {p.sale_price}")

        st.subheader("Edit / Delete")
        if prods:
            sel = st.selectbox("Choose product", options=[
                               (p.id, p.name) for p in prods], format_func=lambda x: x[1])
            if sel:
                p = db.get(Product, sel[0])
                with st.form("edit_prod"):
                    name = st.text_input("Name", value=p.name)
                    category = st.selectbox("Category", options=cat_opts,
                                            index=[i for i, c in enumerate(cat_opts) if c[0] == (p.category_id or (
                                                cat_opts[0][0] if cat_opts else None))][0] if cat_opts else 0,
                                            format_func=lambda x: x[1]) if cat_opts else None
                    qty = st.number_input(
                        "Quantity", min_value=0, value=int(p.quantity), step=1)
                    cost = st.number_input(
                        "Cost price", min_value=0.0, value=float(p.cost_price), step=0.1)
                    price = st.number_input(
                        "Sale price", min_value=0.0, value=float(p.sale_price), step=0.1)
                    new_image = st.file_uploader(
                        "Replace image (optional)", type=["png", "jpg", "jpeg"])
                    save = st.form_submit_button("Save changes")
                c1, c2 = st.columns(2)
                if save:
                    p.name = name.strip()
                    p.category_id = category[0] if category else None
                    p.quantity = int(qty)
                    p.cost_price = float(cost)
                    p.sale_price = float(price)
                    if new_image is not None:
                        ext = os.path.splitext(new_image.name)[1].lower()
                        safe_name = f"product_{int(datetime.utcnow().timestamp())}{ext}"
                        img_path = os.path.join(UPLOAD_DIR, safe_name)
                        with open(img_path, "wb") as f:
                            f.write(new_image.read())
                        p.image_path = img_path
                    db.commit()
                    st.success("Updated.")
                    st.rerun()
                if c2.button("Delete product", type="primary"):
                    if db.query(Sale).filter(Sale.product_id == p.id).first():
                        st.error("Cannot delete: product has sales history.")
                    else:
                        db.delete(p)
                        db.commit()
                        st.success("Deleted.")
                        st.rerun()


def page_sales():
    st.header("Sales")
    with get_db() as db:
        prods = db.query(Product).order_by(Product.name.asc()).all()
        p_opts = [
            (p.id, f"{p.name} (stock {p.quantity}) @ {p.sale_price}") for p in prods]
        with st.form("add_sale", clear_on_submit=True):
            psel = st.selectbox(
                "Product", options=p_opts, format_func=lambda x: x[1] if isinstance(x, tuple) else x)
            qty = st.number_input("Quantity", min_value=1, value=1, step=1)
            when = st.date_input("Date", value=date.today())
            submitted = st.form_submit_button("Record sale")
        if submitted and psel:
            product = db.get(Product, psel[0])
            if product.quantity < qty:
                st.error("Insufficient stock.")
            else:
                product.quantity -= int(qty)
                sale = Sale(
                    product_id=product.id,
                    quantity=int(qty),
                    price_at_sale=float(product.sale_price),
                    sale_date=datetime.combine(when, datetime.min.time()),
                    sold_by=st.session_state.user["id"],
                )
                db.add(sale)
                db.commit()
                st.success("Sale recorded.")
                st.rerun()

        st.subheader("Recent Sales")
        recent = db.query(Sale).order_by(
            Sale.sale_date.desc()).limit(200).all()
        rows = [{
            "ID": s.id,
            "Date": s.sale_date.date().isoformat(),
            "Product": s.product.name if s.product else "?",
            "Qty": s.quantity,
            "Unit Price": s.price_at_sale,
            "Revenue": s.quantity * s.price_at_sale,
            "Sold By": s.sold_by_user.username if s.sold_by_user else None,
        } for s in recent]
        st.dataframe(pd.DataFrame(rows),
                     use_container_width=True, hide_index=True)


def build_sales_frame(db, start_dt: datetime, end_dt: datetime) -> pd.DataFrame:
    q = (
        db.query(Sale.sale_date, Sale.quantity, Sale.price_at_sale,
                 Product.name.label("product"), Category.name.label("category"))
        .join(Product, Sale.product_id == Product.id)
        .outerjoin(Category, Product.category_id == Category.id)
        .filter(Sale.sale_date >= start_dt, Sale.sale_date < end_dt)
        .all()
    )
    return pd.DataFrame([{
        "date": s.sale_date.date(),
        "product": s.product,
        "category": s.category,
        "units": s.quantity,
        "revenue": s.quantity * s.price_at_sale,
    } for s in q])


def page_reports():
    st.header("Reports")
    with get_db() as db:
        colA, colB = st.columns(2)
        with colA:
            mode = st.selectbox(
                "Report Type", ["Daily", "Monthly", "Custom Range"], index=0)
        with colB:
            if mode == "Daily":
                the_day = st.date_input("Pick day", value=date.today())
                start_dt = datetime.combine(the_day, datetime.min.time())
                end_dt = start_dt + relativedelta(days=1)
            elif mode == "Monthly":
                the_month = st.date_input(
                    "Pick any date in month", value=date.today())
                start_dt = datetime(the_month.year, the_month.month, 1)
                end_dt = start_dt + relativedelta(months=1)
            else:
                c1, c2 = st.columns(2)
                with c1:
                    start = st.date_input(
                        "Start date", value=date.today() - relativedelta(days=7))
                with c2:
                    end = st.date_input("End date", value=date.today())
                start_dt = datetime.combine(start, datetime.min.time())
                end_dt = datetime.combine(
                    end,   datetime.min.time()) + relativedelta(days=1)

        df = build_sales_frame(db, start_dt, end_dt)
        if df.empty:
            st.info("No sales in this period.")
            return

        kpis = df.agg({"units": "sum", "revenue": "sum"}).to_dict()
        ucol, rcol = st.columns(2)
        ucol.metric("Units sold", int(kpis.get("units", 0)))
        rcol.metric("Revenue", f"{kpis.get('revenue', 0):,.2f}")

        st.subheader("Revenue by Day")
        day_g = df.groupby("date")["revenue"].sum()
        st.area_chart(day_g)

        st.subheader("Top Products")
        top_p = df.groupby("product")["revenue"].sum(
        ).sort_values(ascending=False).head(10)
        st.bar_chart(top_p)

        st.subheader("By Category")
        by_cat = df.groupby("category")[
            "revenue"].sum().sort_values(ascending=False)
        st.bar_chart(by_cat)

        st.subheader("Raw rows")
        st.dataframe(df.sort_values("date"),
                     use_container_width=True, hide_index=True)
        st.download_button("Download CSV", data=df.to_csv(
            index=False).encode(), file_name="sales_report.csv", mime="text/csv")


def page_users():
    st.header("Users")
    with get_db() as db:
        with st.form("add_user", clear_on_submit=True):
            uname = st.text_input("Username")
            pw = st.text_input("Password", type="password")
            is_admin = st.checkbox("Admin")
            submitted = st.form_submit_button("Create user")
        if submitted:
            if not uname or not pw:
                st.warning("Username and password required.")
            elif db.query(User).filter(func.lower(User.username) == uname.lower()).first():
                st.warning("Username already exists.")
            else:
                db.add(User(username=uname.strip(),
                       password_hash=hash_password(pw), is_admin=is_admin))
                db.commit()
                st.success("User created.")
                st.rerun()

        st.subheader("All Users")
        users = db.query(User).order_by(User.created_at.desc()).all()
        st.dataframe(pd.DataFrame([{
            "ID": u.id, "Username": u.username, "Admin": u.is_admin, "Created": u.created_at
        } for u in users]), use_container_width=True, hide_index=True)

        sel = st.selectbox("Manage user", options=[(
            u.id, u.username) for u in users], format_func=lambda x: x[1] if isinstance(x, tuple) else x)
        if sel:
            u = db.get(User, sel[0])
            col1, col2, col3 = st.columns(3)
            with col1:
                new_pw = st.text_input("Reset password", type="password")
                if st.button("Set password"):
                    if not new_pw:
                        st.warning("Enter a password.")
                    else:
                        u.password_hash = hash_password(new_pw)
                        db.commit()
                        st.success("Password updated.")
            with col2:
                toggle = st.checkbox("Admin", value=u.is_admin)
                if st.button("Save role"):
                    u.is_admin = toggle
                    db.commit()
                    st.success("Role updated.")
            with col3:
                if st.button("Delete user", type="primary"):
                    if u.username == "admin":
                        st.error("Cannot delete default admin.")
                    else:
                        db.delete(u)
                        db.commit()
                        st.success("User deleted.")
                        st.rerun()


def page_settings():
    st.header("Settings & Utilities")
    st.caption("Lightweight tools for export/backup.")
    with get_db() as db:
        prods = db.query(Product).order_by(Product.name.asc()).all()
        p_df = pd.DataFrame([{
            "id": p.id, "name": p.name,
            "category": p.category.name if p.category else None,
            "quantity": p.quantity, "cost_price": p.cost_price, "sale_price": p.sale_price,
            "image_path": p.image_path,
        } for p in prods])
        st.subheader("Export Products")
        st.download_button("Download products.csv", p_df.to_csv(
            index=False).encode(), file_name="products.csv", mime="text/csv")

        st.subheader("Database Snapshot")
        if os.path.exists(DB_PATH):
            with open(DB_PATH, "rb") as f:
                db_bytes = f.read()
            st.download_button("Download inventory.db", db_bytes,
                               file_name="inventory.db", mime="application/octet-stream")

        st.subheader("About")
        st.write(
            "This is an inventory app built with Streamlit + SQLite + SQLAlchemy.")
        st.write(
            "Passwords are hashed with Argon2id (argon2-cffi). For production, also add session/CSRF hardening.")


# -----------------------------
# Main router (single definition)
# -----------------------------
def main():
    init_db()

    if "user" not in st.session_state:
        st.session_state.user = None

    # try to restore from URL token if not logged in
    if st.session_state.user is None:
        restore_session_from_token()

    if st.session_state.user is None:
        login_view()
        return

    topbar()
    page = sidebar_nav()

    if page == "Dashboard":
        page_dashboard()
    elif page == "Products":
        page_products()
    elif page == "Categories":
        page_categories()
    elif page == "Sales":
        page_sales()
    elif page == "Reports":
        page_reports()
    elif page == "Users":
        if st.session_state.user.get("is_admin"):
            page_users()
        else:
            st.error("Admins only.")
    elif page == "Settings":
        page_settings()


if __name__ == "__main__":
    main()

use actix_cors::Cors;
use actix_files::Files;
use actix_governor::{Governor, GovernorConfigBuilder};
use actix_web::{
    cookie::{time::Duration as CookieDuration, Cookie, SameSite},
    delete, get, http::header, middleware, post, put, web::{self, Data, Json, Path, Query},
    App, HttpRequest, HttpResponse, HttpServer, Responder,
};
use aes_gcm::{aead::Aead, Aes128Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose, Engine as _};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone, Utc};
use chrono_tz::Tz;
use csv::Writer;
use hkdf::Hkdf;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use lazy_static::lazy_static;
use lettre::{message::header::ContentType, transport::smtp::authentication::Credentials, AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use log::{error, info};
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    elliptic_curve::sec1::ToEncodedPoint,
    PublicKey, SecretKey,
};
use rand::Rng;
use regex::Regex;
use rusqlite::{params, Connection, Result as SqlResult};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration as StdDuration, Instant},
};
use tokio::time::{interval, Duration};
use uuid::Uuid;

const B64: general_purpose::GeneralPurpose = general_purpose::STANDARD;
const B64URL: general_purpose::GeneralPurpose = general_purpose::URL_SAFE_NO_PAD;

#[derive(Clone)]
struct AppConfig {
    jwt_secret: String,
    admin_user: String,
    admin_pass_hash: String,
    smtp_host: String,
    smtp_port: u16,
    smtp_user: String,
    smtp_pass: String,
    smtp_from: String,
    dev_mode: bool,
    vapid_private_key: String,
    vapid_public_key: String,
}

impl AppConfig {
    fn from_env() -> Self {
        let admin_pass = std::env::var("ADMIN_PASS").unwrap_or_else(|_| "admin123".to_string());
        let admin_pass_hash = hash(&admin_pass, DEFAULT_COST).expect("bcrypt hash failed");
        Self {
            jwt_secret: std::env::var("JWT_SECRET").unwrap_or_else(|_| "clipvue-secret-change-in-production-32chars".to_string()),
            admin_user: std::env::var("ADMIN_USER").unwrap_or_else(|_| "admin".to_string()),
            admin_pass_hash,
            smtp_host: std::env::var("SMTP_HOST").unwrap_or_default(),
            smtp_port: std::env::var("SMTP_PORT").unwrap_or_else(|_| "587".to_string()).parse().unwrap_or(587),
            smtp_user: std::env::var("SMTP_USER").unwrap_or_default(),
            smtp_pass: std::env::var("SMTP_PASS").unwrap_or_default(),
            smtp_from: std::env::var("SMTP_FROM").unwrap_or_else(|_| "noreply@clipvue.com".to_string()),
            dev_mode: std::env::var("DEV_MODE").map(|v| v == "true" || v == "1").unwrap_or(true),
            vapid_private_key: std::env::var("VAPID_PRIVATE_KEY").unwrap_or_default(),
            vapid_public_key: std::env::var("VAPID_PUBLIC_KEY").unwrap_or_default(),
        }
    }
}

type Db = Arc<Mutex<Connection>>;
type RateLimiter = Arc<Mutex<HashMap<String, Vec<Instant>>>>;

fn init_db(path: &str) -> SqlResult<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            phone TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            timezone TEXT NOT NULL DEFAULT 'UTC',
            gdpr_consent INTEGER NOT NULL DEFAULT 0,
            push_subscription TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS barbers (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            photo_base64 TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS slots (
            id TEXT PRIMARY KEY,
            barber_id TEXT NOT NULL REFERENCES barbers(id) ON DELETE CASCADE,
            start_time TEXT NOT NULL,
            end_time TEXT NOT NULL,
            is_available INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS bookings (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            barber_id TEXT NOT NULL REFERENCES barbers(id),
            slot_id TEXT NOT NULL REFERENCES slots(id),
            service_name TEXT NOT NULL,
            selfie_base64 TEXT,
            status TEXT NOT NULL DEFAULT 'confirmed',
            reminder_sent INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS waitlist (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            slot_id TEXT NOT NULL REFERENCES slots(id) ON DELETE CASCADE,
            joined_at TEXT NOT NULL,
            UNIQUE(user_id, slot_id)
        );
        CREATE TABLE IF NOT EXISTS analytics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT NOT NULL,
            ip TEXT,
            user_agent TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS csrf_tokens (
            token TEXT PRIMARY KEY,
            user_id TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS app_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_slots_start ON slots(start_time);
        CREATE INDEX IF NOT EXISTS idx_slots_barber ON slots(barber_id);
        CREATE INDEX IF NOT EXISTS idx_bookings_slot ON bookings(slot_id);
        CREATE INDEX IF NOT EXISTS idx_bookings_user ON bookings(user_id);
        CREATE INDEX IF NOT EXISTS idx_waitlist_slot ON waitlist(slot_id);
        ",
    )?;

    let count: i64 = conn.query_row("SELECT COUNT(*) FROM barbers", [], |row| row.get(0))?;
    if count == 0 {
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO barbers (id, name, photo_base64, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![Uuid::new_v4().to_string(), "7ooda", "", now],
        )?;
    }

    let slot_count: i64 = conn.query_row("SELECT COUNT(*) FROM slots", [], |row| row.get(0))?;
    if slot_count == 0 {
        let barbers: Vec<String> = conn.prepare("SELECT id FROM barbers").unwrap().query_map([], |row| row.get(0)).unwrap().collect::<SqlResult<Vec<String>>>().unwrap();
        let today = Utc::now().date_naive();
        for barber_id in barbers {
            for offset in 0..7 {
                let day = today + chrono::Duration::days(offset);
                for hour in [9, 10, 11, 13, 14, 15, 16] {
                    let start = format!("{}T{:02}:00:00Z", day.format("%Y-%m-%d"), hour);
                    let end = format!("{}T{:02}:30:00Z", day.format("%Y-%m-%d"), hour);
                    let slot_id = Uuid::new_v4().to_string();
                    conn.execute(
                        "INSERT INTO slots (id, barber_id, start_time, end_time, is_available, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        params![slot_id, barber_id, start, end, 1i32, Utc::now().to_rfc3339()],
                    )?;
                }
            }
        }
    }
    Ok(conn)
}

fn get_meta(conn: &Connection, key: &str) -> Option<String> {
    conn.query_row("SELECT value FROM app_meta WHERE key = ?1", [key], |row| row.get(0)).ok()
}

fn set_meta(conn: &Connection, key: &str, value: &str) {
    let _ = conn.execute(
        "INSERT INTO app_meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    );
}

/// Returns (private_key_b64url, public_key_b64url) for VAPID (RFC8292), a P-256 keypair.
/// The public key is the raw 65-byte uncompressed SEC1 point, suitable for
/// PushManager.subscribe({ applicationServerKey }) on the client.
fn generate_vapid_keys() -> (String, String) {
    let secret = SecretKey::random(&mut rand::rngs::OsRng);
    let public = secret.public_key();
    let priv_bytes = secret.to_bytes();
    let pub_point = public.to_encoded_point(false);
    (B64URL.encode(priv_bytes), B64URL.encode(pub_point.as_bytes()))
}

/// Loads VAPID keys from env if both are set, otherwise loads (or generates and persists)
/// a keypair in the app_meta table so it stays stable across restarts.
fn ensure_vapid_keys(conn: &Connection, env_priv: &str, env_pub: &str) -> (String, String) {
    if !env_priv.is_empty() && !env_pub.is_empty() {
        return (env_priv.to_string(), env_pub.to_string());
    }
    if let (Some(priv_k), Some(pub_k)) = (get_meta(conn, "vapid_private"), get_meta(conn, "vapid_public")) {
        return (priv_k, pub_k);
    }
    let (priv_k, pub_k) = generate_vapid_keys();
    set_meta(conn, "vapid_private", &priv_k);
    set_meta(conn, "vapid_public", &pub_k);
    (priv_k, pub_k)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Claims { sub: String, role: String, exp: usize }

fn make_jwt(user_id: &str, role: &str, secret: &str) -> String {
    let exp = (Utc::now() + chrono::Duration::days(7)).timestamp() as usize;
    encode(&Header::default(), &Claims { sub: user_id.to_string(), role: role.to_string(), exp }, &EncodingKey::from_secret(secret.as_bytes())).unwrap()
}

fn verify_jwt(token: &str, secret: &str) -> Option<Claims> {
    decode::<Claims>(token, &DecodingKey::from_secret(secret.as_bytes()), &Validation::default()).ok().map(|d| d.claims)
}

fn jwt_from_req(req: &HttpRequest, secret: &str) -> Option<Claims> {
    req.cookie("token").and_then(|c| verify_jwt(c.value(), secret))
}

fn admin_jwt_from_req(req: &HttpRequest, secret: &str) -> Option<Claims> {
    req.cookie("admin_token").and_then(|c| verify_jwt(c.value(), secret))
}

/// Admin sessions use a separate cookie from user sessions so logging into the
/// admin panel doesn't clobber (or get clobbered by) a customer's own login.
fn set_auth_cookie<'a>(name: &'a str, token: &'a str, dev: bool) -> Cookie<'a> {
    let mut cookie = Cookie::build(name, token)
        .path("/")
        .http_only(true)
        .same_site(SameSite::Strict)
        .max_age(CookieDuration::days(7))
        .finish();
    if !dev { cookie.set_secure(true); }
    cookie
}

fn client_ip(req: &HttpRequest) -> String {
    req.connection_info().realip_remote_addr().unwrap_or("unknown").to_string()
}

lazy_static! {
    static ref HTML_TAG: Regex = Regex::new(r"<[^>]*>").unwrap();
}

fn sanitise(input: &str) -> String { HTML_TAG.replace_all(input.trim(), "").to_string() }

fn valid_image(b64: &Option<String>) -> bool {
    let Some(b64) = b64 else { return true; };
    if b64.is_empty() { return true; }
    if b64.len() > 270_000 { return false; }
    let Ok(bytes) = B64.decode(b64) else { return false; };
    if bytes.len() > 200_000 { return false; }
    bytes.starts_with(b"\x89PNG") || bytes.starts_with(b"\xff\xd8\xff")
}

fn gen_csrf() -> String {
    let mut rng = rand::thread_rng();
    (0..32).map(|_| format!("{:02x}", rng.gen::<u8>())).collect()
}

/// Simple sliding-window limiter: `limit` requests per 60s per key.
fn check_rate_limit(key: &str, limiter: &RateLimiter, limit: usize) -> bool {
    let mut map = limiter.lock().unwrap();
    let now = Instant::now();
    let window = map.entry(key.to_string()).or_default();
    window.retain(|t| now.duration_since(*t) < StdDuration::from_secs(60));
    if window.len() >= limit {
        return false;
    }
    window.push(now);
    true
}

fn require_csrf(req: &HttpRequest, db: &Db) -> Result<(), HttpResponse> {
    let header = req.headers().get("x-csrf-token").and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
    let cookie = req.cookie("csrf_token").map(|c| c.value().to_string()).unwrap_or_default();
    let token = if header.is_empty() { cookie } else { header };
    if token.is_empty() { return Err(HttpResponse::Forbidden().json(json!({"error": "CSRF token required"}))); }
    let conn = db.lock().unwrap();
    let exists: i64 = conn.query_row("SELECT COUNT(*) FROM csrf_tokens WHERE token = ?1", [token], |row| row.get(0)).unwrap_or(0);
    if exists == 0 { return Err(HttpResponse::Forbidden().json(json!({"error": "Invalid CSRF token"}))); }
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct SignupBody { name: String, phone: String, password: String, timezone: Option<String>, gdpr_consent: bool }
#[derive(Serialize, Deserialize)]
struct LoginBody { phone: String, password: String }
#[derive(Serialize, Deserialize)]
struct AdminLoginBody { username: String, password: String }
#[derive(Serialize, Deserialize, Clone)]
struct UserRow { id: String, name: String, phone: String, timezone: String, gdpr_consent: bool, created_at: String }
#[derive(Serialize, Deserialize, Clone)]
struct BarberRow { id: String, name: String, photo_base64: Option<String>, created_at: String }
#[derive(Serialize, Deserialize, Clone)]
struct BookingRow { id: String, user_id: String, barber_id: String, slot_id: String, service_name: String, selfie_base64: Option<String>, status: String, created_at: String, user_name: Option<String>, barber_name: Option<String>, slot_start: Option<String> }
#[derive(Serialize, Deserialize)]
struct CreateBookingBody { slot_id: String, service_name: String, selfie_base64: Option<String> }
#[derive(Serialize, Deserialize)]
struct RescheduleBody { slot_id: String }
#[derive(Serialize, Deserialize)]
struct CreateBarberBody { name: String, photo_base64: Option<String> }
#[derive(Serialize, Deserialize)]
struct CreateSlotBody { barber_id: String, date: String, start_time: String, end_time: String, interval_minutes: i64, timezone: Option<String> }
#[derive(Serialize, Deserialize)]
struct SlotsQuery { date: Option<String>, barber_id: Option<String>, include_unavailable: Option<String> }
#[derive(Serialize, Deserialize)]
struct WaitlistBody { slot_id: String }
#[derive(Serialize, Deserialize)]
struct UpdateBookingBody { status: Option<String>, service_name: Option<String>, start_time: Option<String>, timezone: Option<String> }
#[derive(Serialize, Deserialize)]
struct UpdateSlotBody { is_available: Option<bool> }
#[derive(Serialize, Deserialize)]
struct AnalyticsBody { path: String }
#[derive(Serialize, Deserialize)]
struct PushSubBody { subscription: serde_json::Value }

async fn csrf_token(req: HttpRequest, db: Data<Db>, cfg: Data<AppConfig>) -> impl Responder {
    let token = gen_csrf();
    let conn = db.lock().unwrap();
    let cutoff = (Utc::now() - chrono::Duration::hours(24)).to_rfc3339();
    let _ = conn.execute("DELETE FROM csrf_tokens WHERE created_at < ?1", params![cutoff]);
    let _ = conn.execute("INSERT INTO csrf_tokens (token, user_id, created_at) VALUES (?1, ?2, ?3)", params![token, jwt_from_req(&req, &cfg.jwt_secret).map(|c| c.sub), Utc::now().to_rfc3339()]);
    let cookie = Cookie::build("csrf_token", token.clone()).path("/").http_only(false).same_site(SameSite::Strict).max_age(CookieDuration::hours(1)).finish();
    HttpResponse::Ok().cookie(cookie).json(json!({"csrf_token": token}))
}

#[post("/api/auth/signup")]
async fn signup(body: Json<SignupBody>, db: Data<Db>, cfg: Data<AppConfig>, req: HttpRequest, limiter: Data<RateLimiter>) -> impl Responder {
    if let Err(resp) = require_csrf(&req, &db) { return resp; }
    if !check_rate_limit(&format!("signup:{}", client_ip(&req)), &limiter, 5) { return HttpResponse::TooManyRequests().json(json!({"error":"Too many attempts, try again later"})); }
    if !body.gdpr_consent { return HttpResponse::BadRequest().json(json!({"error":"GDPR consent required"})); }
    let name = sanitise(&body.name);
    let phone = sanitise(&body.phone);
    if name.is_empty() || phone.len() < 7 || body.password.len() < 6 { return HttpResponse::BadRequest().json(json!({"error":"Invalid input"})); }
    let pass_hash = hash(&body.password, DEFAULT_COST).unwrap();
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let timezone = sanitise(&body.timezone.clone().unwrap_or_else(|| "UTC".to_string()));
    let conn = db.lock().unwrap();
    match conn.execute("INSERT INTO users (id, name, phone, password_hash, timezone, gdpr_consent, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)", params![id, name, phone, pass_hash, timezone, 1i32, now]) {
        Ok(_) => {}
        Err(e) => { if e.to_string().contains("UNIQUE") { return HttpResponse::Conflict().json(json!({"error":"Phone already registered"})); } error!("signup error: {e}"); return HttpResponse::InternalServerError().finish(); }
    }
    let token = make_jwt(&id, "user", &cfg.jwt_secret);
    let cookie = set_auth_cookie("token", &token, cfg.dev_mode);
    HttpResponse::Ok().cookie(cookie).json(json!({"user": {"id": id, "name": name, "phone": phone, "timezone": timezone}}))
}

#[post("/api/auth/login")]
async fn login(body: Json<LoginBody>, db: Data<Db>, cfg: Data<AppConfig>, req: HttpRequest, limiter: Data<RateLimiter>) -> impl Responder {
    if let Err(resp) = require_csrf(&req, &db) { return resp; }
    if !check_rate_limit(&format!("login:{}", client_ip(&req)), &limiter, 5) { return HttpResponse::TooManyRequests().json(json!({"error":"Too many attempts, try again later"})); }
    let phone = sanitise(&body.phone);
    let password = body.password.trim();
    let conn = db.lock().unwrap();
    let mut stmt = match conn.prepare("SELECT id, password_hash, name, timezone FROM users WHERE phone = ?1") { Ok(s)=>s, Err(_)=>return HttpResponse::Unauthorized().json(json!({"error":"Invalid credentials"}))};
    let user = stmt.query_row([phone], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?))).ok();
    let Some((id, hash, name, timezone)) = user else { return HttpResponse::Unauthorized().json(json!({"error":"Invalid credentials"})); };
    if verify(password, &hash).unwrap_or(false) {
        let token = make_jwt(&id, "user", &cfg.jwt_secret);
        let cookie = set_auth_cookie("token", &token, cfg.dev_mode);
        HttpResponse::Ok().cookie(cookie).json(json!({"user": {"id": id, "name": name, "timezone": timezone}}))
    } else {
        HttpResponse::Unauthorized().json(json!({"error":"Invalid credentials"}))
    }
}

#[post("/api/auth/logout")]
async fn logout(req: HttpRequest, db: Data<Db>) -> impl Responder {
    if let Err(resp) = require_csrf(&req, &db) { return resp; }
    let cookie = Cookie::build("token", "").path("/").http_only(true).same_site(SameSite::Strict).max_age(CookieDuration::seconds(0)).finish();
    HttpResponse::Ok().cookie(cookie).json(json!({"ok": true}))
}

#[get("/api/auth/me")]
async fn me(req: HttpRequest, db: Data<Db>, cfg: Data<AppConfig>) -> impl Responder {
    let Some(claims) = jwt_from_req(&req, &cfg.jwt_secret) else { return HttpResponse::Unauthorized().json(json!({"error":"Unauthenticated"})); };
    let conn = db.lock().unwrap();
    let mut stmt = match conn.prepare("SELECT id, name, phone, timezone, gdpr_consent, created_at FROM users WHERE id = ?1") { Ok(s)=>s, Err(_)=>return HttpResponse::Unauthorized().json(json!({"error":"User missing"}))};
    let user = stmt.query_row([claims.sub], |row| Ok(UserRow { id: row.get(0)?, name: row.get(1)?, phone: row.get(2)?, timezone: row.get(3)?, gdpr_consent: row.get(4)?, created_at: row.get(5)? })).ok();
    match user { Some(u)=> HttpResponse::Ok().json(json!({"user": u})), None=> HttpResponse::Unauthorized().json(json!({"error":"User missing"})) }
}

#[post("/api/admin/login")]
async fn admin_login(body: Json<AdminLoginBody>, db: Data<Db>, cfg: Data<AppConfig>, req: HttpRequest, limiter: Data<RateLimiter>) -> impl Responder {
    if let Err(resp) = require_csrf(&req, &db) { return resp; }
    if !check_rate_limit(&format!("admin_login:{}", client_ip(&req)), &limiter, 5) { return HttpResponse::TooManyRequests().json(json!({"error":"Too many attempts, try again later"})); }
    let username = sanitise(&body.username);
    let password = body.password.trim();
    if username != cfg.admin_user || !verify(password, &cfg.admin_pass_hash).unwrap_or(false) { return HttpResponse::Unauthorized().json(json!({"error":"Invalid admin credentials"})); }
    let token = make_jwt(&username, "admin", &cfg.jwt_secret);
    let cookie = set_auth_cookie("admin_token", &token, cfg.dev_mode);
    HttpResponse::Ok().cookie(cookie).json(json!({"ok": true}))
}

#[post("/api/admin/logout")]
async fn admin_logout(req: HttpRequest, db: Data<Db>) -> impl Responder {
    if let Err(resp) = require_csrf(&req, &db) { return resp; }
    let cookie = Cookie::build("admin_token", "").path("/").http_only(true).same_site(SameSite::Strict).max_age(CookieDuration::seconds(0)).finish();
    HttpResponse::Ok().cookie(cookie).json(json!({"ok": true}))
}

#[get("/api/admin/me")]
async fn admin_me(req: HttpRequest, cfg: Data<AppConfig>) -> impl Responder {
    match require_admin(&req, &cfg) {
        Ok(_) => HttpResponse::Ok().json(json!({"admin": true})),
        Err(resp) => resp,
    }
}

fn require_admin(req: &HttpRequest, cfg: &AppConfig) -> Result<Claims, HttpResponse> {
    let claims = admin_jwt_from_req(req, &cfg.jwt_secret).ok_or_else(|| HttpResponse::Unauthorized().json(json!({"error":"Admin required"})))?;
    if claims.role != "admin" { return Err(HttpResponse::Forbidden().json(json!({"error":"Admin required"}))); }
    Ok(claims)
}

#[get("/api/admin/dashboard")]
async fn admin_dashboard(db: Data<Db>, req: HttpRequest, cfg: Data<AppConfig>, query: Query<HashMap<String, String>>) -> impl Responder {
    if let Err(resp) = require_admin(&req, &cfg) { return resp; }
    let conn = db.lock().unwrap();

    // "Clients on <day>" is counted by appointment time (the slot), in Cairo local days,
    // so it answers "how many clients on this date" rather than "how many booked today".
    let tz = chrono_tz::Tz::Africa__Cairo;
    let day = query.get("date")
        .and_then(|d| NaiveDate::parse_from_str(d, "%Y-%m-%d").ok())
        .unwrap_or_else(|| Utc::now().with_timezone(&tz).date_naive());
    let day_start_utc = tz.from_local_datetime(&day.and_hms_opt(0, 0, 0).unwrap()).single()
        .map(|dt| dt.with_timezone(&Utc)).unwrap_or_else(Utc::now);
    let day_end_utc = day_start_utc + chrono::Duration::days(1);
    let (rng_start, rng_end) = (day_start_utc.format("%Y-%m-%dT%H:%M:%SZ").to_string(), day_end_utc.format("%Y-%m-%dT%H:%M:%SZ").to_string());
    // Clients scheduled that day, excluding cancellations.
    let clients_on_date: i64 = conn.query_row(
        "SELECT COUNT(*) FROM bookings b JOIN slots s ON s.id = b.slot_id WHERE b.status != 'cancelled' AND s.start_time >= ?1 AND s.start_time < ?2",
        params![rng_start, rng_end], |row| row.get(0)).unwrap_or(0);

    let bookings_total: i64 = conn.query_row("SELECT COUNT(*) FROM bookings", [], |row| row.get(0)).unwrap_or(0);
    let week: i64 = conn.query_row("SELECT COUNT(*) FROM bookings WHERE created_at >= ?1", [Utc::now().checked_sub_signed(chrono::Duration::days(7)).unwrap().to_rfc3339()], |row| row.get(0)).unwrap_or(0);
    let no_shows: i64 = conn.query_row("SELECT COUNT(*) FROM bookings WHERE status = 'no_show'", [], |row| row.get(0)).unwrap_or(0);
    let cancelled: i64 = conn.query_row("SELECT COUNT(*) FROM bookings WHERE status = 'cancelled'", [], |row| row.get(0)).unwrap_or(0);
    let pageviews: i64 = conn.query_row("SELECT COUNT(*) FROM analytics", [], |row| row.get(0)).unwrap_or(0);
    let popular: Vec<serde_json::Value> = conn.prepare("SELECT b.name, COUNT(*) as count FROM bookings bk JOIN barbers b ON b.id = bk.barber_id GROUP BY b.id ORDER BY count DESC LIMIT 5").unwrap().query_map([], |row| Ok(json!({"name": row.get::<_, String>(0)?, "count": row.get::<_, i64>(1)?}))).unwrap().filter_map(|v| v.ok()).collect();
    HttpResponse::Ok().json(json!({"date": day.format("%Y-%m-%d").to_string(), "clients_on_date": clients_on_date, "bookings_total": bookings_total, "bookings_week": week, "no_shows": no_shows, "cancelled": cancelled, "pageviews": pageviews, "popular_barbers": popular}))
}

#[get("/api/admin/bookings")]
async fn admin_bookings(db: Data<Db>, req: HttpRequest, cfg: Data<AppConfig>, query: Query<HashMap<String, String>>) -> impl Responder {
    if let Err(resp) = require_admin(&req, &cfg) { return resp; }
    let conn = db.lock().unwrap();
    let mut sql = "SELECT b.id, b.user_id, b.barber_id, b.slot_id, b.service_name, b.selfie_base64, b.status, b.created_at, u.name, br.name, s.start_time, u.phone FROM bookings b JOIN users u ON u.id = b.user_id JOIN barbers br ON br.id = b.barber_id JOIN slots s ON s.id = b.slot_id WHERE 1=1".to_string();
    let mut params_vec: Vec<String> = Vec::new();
    if let Some(status) = query.get("status") { if !status.is_empty() { sql.push_str(" AND b.status = ?"); params_vec.push(status.clone()); } }
    if let Some(barber_id) = query.get("barber_id") { if !barber_id.is_empty() { sql.push_str(" AND b.barber_id = ?"); params_vec.push(barber_id.clone()); } }
    // Filter by a Cairo-local calendar day (matches the dashboard's per-day count).
    if let Some(date) = query.get("date") {
        if let Ok(d) = NaiveDate::parse_from_str(date, "%Y-%m-%d") {
            let tz = chrono_tz::Tz::Africa__Cairo;
            if let Some(start) = tz.from_local_datetime(&d.and_hms_opt(0, 0, 0).unwrap()).single() {
                let start_utc = start.with_timezone(&Utc);
                let end_utc = start_utc + chrono::Duration::days(1);
                sql.push_str(" AND s.start_time >= ? AND s.start_time < ?");
                params_vec.push(start_utc.format("%Y-%m-%dT%H:%M:%SZ").to_string());
                params_vec.push(end_utc.format("%Y-%m-%dT%H:%M:%SZ").to_string());
            }
        }
    }
    let dir = if query.get("sort").map(|s| s.as_str()) == Some("asc") { "ASC" } else { "DESC" };
    sql.push_str(&format!(" ORDER BY s.start_time {dir}"));
    let mut stmt = conn.prepare(&sql).unwrap();
    let bookings = stmt.query_map(rusqlite::params_from_iter(params_vec.iter()), |row| Ok(json!({
        "id": row.get::<_, String>(0)?, "user_id": row.get::<_, String>(1)?, "barber_id": row.get::<_, String>(2)?,
        "slot_id": row.get::<_, String>(3)?, "service_name": row.get::<_, String>(4)?, "selfie_base64": row.get::<_, Option<String>>(5)?,
        "status": row.get::<_, String>(6)?, "created_at": row.get::<_, String>(7)?, "user_name": row.get::<_, Option<String>>(8)?,
        "barber_name": row.get::<_, Option<String>>(9)?, "slot_start": row.get::<_, Option<String>>(10)?, "user_phone": row.get::<_, Option<String>>(11)?
    }))).unwrap().filter_map(|v| v.ok()).collect::<Vec<_>>();
    HttpResponse::Ok().json(json!({"bookings": bookings}))
}

#[put("/api/admin/bookings/{id}")]
async fn update_admin_booking(path: Path<String>, body: Json<UpdateBookingBody>, db: Data<Db>, req: HttpRequest, cfg: Data<AppConfig>) -> impl Responder {
    if let Err(resp) = require_csrf(&req, &db) { return resp; }
    if let Err(resp) = require_admin(&req, &cfg) { return resp; }
    let id = path.into_inner();
    let new_status = body.status.clone().map(|s| sanitise(&s));
    let new_service = body.service_name.clone().map(|s| sanitise(&s));
    let conn = db.lock().unwrap();
    if let Some(status) = new_status { conn.execute("UPDATE bookings SET status = ?1 WHERE id = ?2", params![status, id]).unwrap(); }
    if let Some(service) = new_service { conn.execute("UPDATE bookings SET service_name = ?1 WHERE id = ?2", params![service, id]).unwrap(); }
    // Full time control: admin supplies a local wall-clock time (Cairo by default); we
    // reinterpret it in that zone -> UTC and rewrite this booking's slot, preserving duration.
    if let Some(start_local) = body.start_time.clone() {
        let start_local = start_local.trim().to_string();
        if !start_local.is_empty() {
            if let Some((slot_id, old_start, old_end)) = conn.query_row(
                "SELECT s.id, s.start_time, s.end_time FROM bookings b JOIN slots s ON s.id = b.slot_id WHERE b.id = ?1",
                [id.clone()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)),
            ).ok() {
                let tzn: Tz = body.timezone.clone().unwrap_or_else(|| "Africa/Cairo".to_string()).parse().unwrap_or(chrono_tz::Tz::Africa__Cairo);
                // Accept both "YYYY-MM-DDTHH:MM" (datetime-local) and with seconds.
                let naive = NaiveDateTime::parse_from_str(&start_local, "%Y-%m-%dT%H:%M")
                    .or_else(|_| NaiveDateTime::parse_from_str(&start_local, "%Y-%m-%dT%H:%M:%S"));
                if let Ok(naive) = naive {
                    let duration = match (DateTime::parse_from_rfc3339(&old_start), DateTime::parse_from_rfc3339(&old_end)) {
                        (Ok(s), Ok(e)) => e - s,
                        _ => chrono::Duration::minutes(30),
                    };
                    if let Some(local_dt) = tzn.from_local_datetime(&naive).single() {
                        let start_utc = local_dt.with_timezone(&Utc);
                        let end_utc = start_utc + duration;
                        conn.execute(
                            "UPDATE slots SET start_time = ?1, end_time = ?2 WHERE id = ?3",
                            params![start_utc.format("%Y-%m-%dT%H:%M:%SZ").to_string(), end_utc.format("%Y-%m-%dT%H:%M:%SZ").to_string(), slot_id],
                        ).unwrap();
                        conn.execute("UPDATE bookings SET reminder_sent = 0 WHERE id = ?1", params![id]).unwrap();
                    } else {
                        return HttpResponse::BadRequest().json(json!({"error":"Invalid or ambiguous time"}));
                    }
                } else {
                    return HttpResponse::BadRequest().json(json!({"error":"Invalid time format"}));
                }
            }
        }
    }
    HttpResponse::Ok().json(json!({"ok": true}))
}

#[delete("/api/admin/bookings/{id}")]
async fn delete_admin_booking(path: Path<String>, db: Data<Db>, req: HttpRequest, cfg: Data<AppConfig>) -> impl Responder {
    if let Err(resp) = require_csrf(&req, &db) { return resp; }
    if let Err(resp) = require_admin(&req, &cfg) { return resp; }
    let id = path.into_inner();
    let conn = db.lock().unwrap();
    let slot_id: Option<String> = conn.query_row("SELECT slot_id FROM bookings WHERE id = ?1", [id.clone()], |row| row.get(0)).ok();
    conn.execute("DELETE FROM bookings WHERE id = ?1", params![id]).unwrap();
    if let Some(slot_id) = slot_id { conn.execute("UPDATE slots SET is_available = 1 WHERE id = ?1", params![slot_id]).unwrap(); }
    HttpResponse::Ok().json(json!({"ok": true}))
}

#[post("/api/admin/barbers")]
async fn create_barber(body: Json<CreateBarberBody>, db: Data<Db>, req: HttpRequest, cfg: Data<AppConfig>) -> impl Responder {
    if let Err(resp) = require_csrf(&req, &db) { return resp; }
    if let Err(resp) = require_admin(&req, &cfg) { return resp; }
    let name = sanitise(&body.name);
    if name.is_empty() { return HttpResponse::BadRequest().json(json!({"error":"Name required"})); }
    let photo = body.photo_base64.as_ref().map(|s| sanitise(s));
    if !valid_image(&photo) { return HttpResponse::BadRequest().json(json!({"error":"Invalid image"})); }
    let id = Uuid::new_v4().to_string();
    let conn = db.lock().unwrap();
    conn.execute("INSERT INTO barbers (id, name, photo_base64, created_at) VALUES (?1, ?2, ?3, ?4)", params![id, name, photo, Utc::now().to_rfc3339()]).unwrap();
    HttpResponse::Ok().json(json!({"barber": {"id": id, "name": name}}))
}

#[delete("/api/admin/barbers/{id}")]
async fn delete_barber(path: Path<String>, db: Data<Db>, req: HttpRequest, cfg: Data<AppConfig>) -> impl Responder {
    if let Err(resp) = require_csrf(&req, &db) { return resp; }
    if let Err(resp) = require_admin(&req, &cfg) { return resp; }
    let id = path.into_inner();
    let conn = db.lock().unwrap();
    // Remove the barber's bookings first (bookings.barber_id has no cascade, so a
    // straight barber delete would fail the FK check when bookings exist). Slots and
    // any waitlist entries are then removed by ON DELETE CASCADE when the barber goes.
    conn.execute("DELETE FROM bookings WHERE barber_id = ?1", params![id]).unwrap();
    conn.execute("DELETE FROM barbers WHERE id = ?1", params![id]).unwrap();
    HttpResponse::Ok().json(json!({"ok": true}))
}

#[post("/api/admin/slots")]
async fn create_slots(body: Json<CreateSlotBody>, db: Data<Db>, req: HttpRequest, cfg: Data<AppConfig>) -> impl Responder {
    if let Err(resp) = require_csrf(&req, &db) { return resp; }
    if let Err(resp) = require_admin(&req, &cfg) { return resp; }
    let timezone = body.timezone.clone().unwrap_or_else(|| "UTC".to_string());
    let start = body.start_time.trim().to_string();
    let end = body.end_time.trim().to_string();
    let interval = body.interval_minutes.max(15);
    let conn = db.lock().unwrap();
    let day = NaiveDate::parse_from_str(&body.date, "%Y-%m-%d").unwrap_or_else(|_| Utc::now().date_naive());
    let tzn: Tz = timezone.parse().unwrap_or(chrono_tz::UTC);
    let start_dt = format!("{} {}", day.format("%Y-%m-%d"), start);
    let end_dt = format!("{} {}", day.format("%Y-%m-%d"), end);
    let start_naive = NaiveDateTime::parse_from_str(&start_dt, "%Y-%m-%d %H:%M").unwrap_or_else(|_| Utc::now().naive_utc());
    let end_naive = NaiveDateTime::parse_from_str(&end_dt, "%Y-%m-%d %H:%M").unwrap_or_else(|_| Utc::now().naive_utc());
    let start_utc = tzn.from_local_datetime(&start_naive).single().unwrap_or_else(|| Utc::now().with_timezone(&tzn)).with_timezone(&Utc).naive_utc();
    let end_utc = tzn.from_local_datetime(&end_naive).single().unwrap_or_else(|| Utc::now().with_timezone(&tzn)).with_timezone(&Utc).naive_utc();
    let mut cursor = start_utc;
    let mut created = 0i32;
    while cursor < end_utc {
        let next = cursor + chrono::Duration::minutes(interval);
        if next > end_utc { break; }
        let slot_id = Uuid::new_v4().to_string();
        conn.execute("INSERT INTO slots (id, barber_id, start_time, end_time, is_available, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)", params![slot_id, body.barber_id, cursor.format("%Y-%m-%dT%H:%M:%SZ").to_string(), next.format("%Y-%m-%dT%H:%M:%SZ").to_string(), 1i32, Utc::now().to_rfc3339()]).unwrap();
        cursor = next;
        created += 1;
    }
    HttpResponse::Ok().json(json!({"ok": true, "created": created}))
}

#[get("/api/admin/slots")]
async fn admin_list_slots(db: Data<Db>, req: HttpRequest, cfg: Data<AppConfig>, query: Query<SlotsQuery>) -> impl Responder {
    if let Err(resp) = require_admin(&req, &cfg) { return resp; }
    let conn = db.lock().unwrap();
    let mut sql = "SELECT s.id, s.barber_id, s.start_time, s.end_time, s.is_available, br.name FROM slots s JOIN barbers br ON br.id = s.barber_id WHERE 1=1".to_string();
    let mut params_vec: Vec<String> = Vec::new();
    if let Some(date) = &query.date { if !date.is_empty() { sql.push_str(" AND s.start_time LIKE ?"); params_vec.push(format!("{}%", date)); } }
    if let Some(barber_id) = &query.barber_id { if !barber_id.is_empty() { sql.push_str(" AND s.barber_id = ?"); params_vec.push(barber_id.clone()); } }
    sql.push_str(" ORDER BY s.start_time");
    let mut stmt = conn.prepare(&sql).unwrap();
    let rows = stmt.query_map(rusqlite::params_from_iter(params_vec.iter()), |row| Ok(json!({"id": row.get::<_, String>(0)?, "barber_id": row.get::<_, String>(1)?, "start_time": row.get::<_, String>(2)?, "end_time": row.get::<_, String>(3)?, "is_available": row.get::<_, i32>(4)?, "barber_name": row.get::<_, String>(5)?}))).unwrap().filter_map(|v| v.ok()).collect::<Vec<_>>();
    HttpResponse::Ok().json(json!({"slots": rows}))
}

#[put("/api/admin/slots/{id}")]
async fn update_slot(path: Path<String>, body: Json<UpdateSlotBody>, db: Data<Db>, req: HttpRequest, cfg: Data<AppConfig>) -> impl Responder {
    if let Err(resp) = require_csrf(&req, &db) { return resp; }
    if let Err(resp) = require_admin(&req, &cfg) { return resp; }
    let id = path.into_inner();
    let available = body.is_available.unwrap_or(true);
    let conn = db.lock().unwrap();
    conn.execute("UPDATE slots SET is_available = ?1 WHERE id = ?2", params![if available { 1i32 } else { 0i32 }, id]).unwrap();
    HttpResponse::Ok().json(json!({"ok": true}))
}

#[delete("/api/admin/slots/{id}")]
async fn delete_slot(path: Path<String>, db: Data<Db>, req: HttpRequest, cfg: Data<AppConfig>) -> impl Responder {
    if let Err(resp) = require_csrf(&req, &db) { return resp; }
    if let Err(resp) = require_admin(&req, &cfg) { return resp; }
    let id = path.into_inner();
    let conn = db.lock().unwrap();
    conn.execute("DELETE FROM slots WHERE id = ?1", params![id]).unwrap();
    HttpResponse::Ok().json(json!({"ok": true}))
}

#[get("/api/admin/export/csv")]
async fn export_csv(db: Data<Db>, req: HttpRequest, cfg: Data<AppConfig>) -> impl Responder {
    if let Err(resp) = require_admin(&req, &cfg) { return resp; }
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare("SELECT b.id, u.name, br.name, s.start_time, b.service_name, b.status FROM bookings b JOIN users u ON u.id = b.user_id JOIN barbers br ON br.id = b.barber_id JOIN slots s ON s.id = b.slot_id ORDER BY b.created_at DESC").unwrap();
    let mut w = Writer::from_writer(Vec::new());
    w.write_record(["id", "customer", "barber", "time", "service", "status"]).unwrap();
    for row in stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, String>(4)?, row.get::<_, String>(5)?))).unwrap().filter_map(|v| v.ok()) {
        w.write_record([row.0, row.1, row.2, row.3, row.4, row.5]).unwrap();
    }
    let bytes = String::from_utf8(w.into_inner().unwrap()).unwrap();
    HttpResponse::Ok().insert_header((header::CONTENT_TYPE, "text/csv; charset=utf-8")).insert_header((header::CONTENT_DISPOSITION, "attachment; filename=\"clipvue-bookings.csv\"")).body(bytes)
}

#[get("/api/barbers")]
async fn list_barbers(db: Data<Db>) -> impl Responder {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare("SELECT id, name, photo_base64, created_at FROM barbers ORDER BY name").unwrap();
    let barbers = stmt.query_map([], |row| Ok(BarberRow { id: row.get(0)?, name: row.get(1)?, photo_base64: row.get(2).ok(), created_at: row.get(3)? })).unwrap().filter_map(|v| v.ok()).collect::<Vec<_>>();
    HttpResponse::Ok().json(json!({"barbers": barbers}))
}

#[get("/api/slots")]
async fn list_slots(db: Data<Db>, query: Query<SlotsQuery>) -> impl Responder {
    let conn = db.lock().unwrap();
    let include_unavailable = query.include_unavailable.as_deref() == Some("1");
    let mut sql = "SELECT id, barber_id, start_time, end_time, is_available FROM slots WHERE 1=1".to_string();
    if !include_unavailable { sql.push_str(" AND is_available = 1"); }
    let mut params_vec: Vec<String> = Vec::new();
    if let Some(date) = &query.date { sql.push_str(" AND start_time LIKE ?"); params_vec.push(format!("{}%", date)); }
    if let Some(barber_id) = &query.barber_id { sql.push_str(" AND barber_id = ?"); params_vec.push(barber_id.clone()); }
    sql.push_str(" ORDER BY start_time");
    let mut stmt = conn.prepare(&sql).unwrap();
    let rows = stmt.query_map(rusqlite::params_from_iter(params_vec.iter().map(|s| s.as_str())), |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, i32>(4)?))).unwrap().filter_map(|v| v.ok()).collect::<Vec<_>>();
    let slots: Vec<serde_json::Value> = rows.into_iter().map(|(id, barber_id, start_time, end_time, is_available)| {
        let waitlist_count: i64 = conn.query_row("SELECT COUNT(*) FROM waitlist WHERE slot_id = ?1", [&id], |row| row.get(0)).unwrap_or(0);
        json!({"id": id, "barber_id": barber_id, "start_time": start_time, "end_time": end_time, "is_available": is_available, "waitlist_count": waitlist_count})
    }).collect();
    HttpResponse::Ok().json(json!({"slots": slots}))
}

#[post("/api/bookings")]
async fn create_booking(body: Json<CreateBookingBody>, db: Data<Db>, req: HttpRequest, cfg: Data<AppConfig>) -> impl Responder {
    if let Err(resp) = require_csrf(&req, &db) { return resp; }
    let Some(claims) = jwt_from_req(&req, &cfg.jwt_secret) else { return HttpResponse::Unauthorized().json(json!({"error":"Login required"})); };
    let service = sanitise(&body.service_name);
    if service.is_empty() { return HttpResponse::BadRequest().json(json!({"error":"Service required"})); }
    if !valid_image(&body.selfie_base64) { return HttpResponse::BadRequest().json(json!({"error":"Invalid image"})); }
    let conn = db.lock().unwrap();
    // A customer can't hold a booking and a waitlist spot at the same time.
    let on_waitlist: i64 = conn.query_row("SELECT COUNT(*) FROM waitlist WHERE user_id = ?1", [claims.sub.clone()], |row| row.get(0)).unwrap_or(0);
    if on_waitlist > 0 { return HttpResponse::Conflict().json(json!({"error":"You're on a waitlist — leave it before booking a slot"})); }
    let slot_exists: i64 = conn.query_row("SELECT COUNT(*) FROM slots WHERE id = ?1 AND is_available = 1", [body.slot_id.clone()], |row| row.get(0)).unwrap_or(0);
    if slot_exists == 0 { return HttpResponse::Conflict().json(json!({"error":"Slot unavailable"})); }
    let already: i64 = conn.query_row("SELECT COUNT(*) FROM bookings WHERE slot_id = ?1", [body.slot_id.clone()], |row| row.get(0)).unwrap_or(0);
    if already > 0 { return HttpResponse::Conflict().json(json!({"error":"Slot already booked"})); }
    let barber_id: String = conn.query_row("SELECT barber_id FROM slots WHERE id = ?1", [body.slot_id.clone()], |row| row.get(0)).unwrap_or_default();
    let id = Uuid::new_v4().to_string();
    conn.execute("INSERT INTO bookings (id, user_id, barber_id, slot_id, service_name, selfie_base64, status, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)", params![id, claims.sub, barber_id, body.slot_id, service, body.selfie_base64.as_ref().map(|s| s.trim()).unwrap_or_default(), "confirmed", Utc::now().to_rfc3339()]).unwrap();
    conn.execute("UPDATE slots SET is_available = 0 WHERE id = ?1", params![body.slot_id]).unwrap();
    HttpResponse::Ok().json(json!({"booking": {"id": id, "service": service}}))
}

#[put("/api/bookings/{id}/reschedule")]
async fn reschedule_booking(path: Path<String>, body: Json<RescheduleBody>, db: Data<Db>, req: HttpRequest, cfg: Data<AppConfig>) -> impl Responder {
    if let Err(resp) = require_csrf(&req, &db) { return resp; }
    let Some(claims) = jwt_from_req(&req, &cfg.jwt_secret) else { return HttpResponse::Unauthorized().json(json!({"error":"Login required"})); };
    let id = path.into_inner();
    let conn = db.lock().unwrap();
    let booking: Option<(String, String, String)> = conn.query_row("SELECT slot_id, user_id, barber_id FROM bookings WHERE id = ?1", [id.clone()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).ok();
    let Some((old_slot_id, user_id, barber_id)) = booking else { return HttpResponse::NotFound().json(json!({"error":"Booking not found"})); };
    if user_id != claims.sub { return HttpResponse::Forbidden().json(json!({"error":"Not your booking"})); }
    let new_slot_barber: Option<String> = conn.query_row("SELECT barber_id FROM slots WHERE id = ?1 AND is_available = 1", [body.slot_id.clone()], |row| row.get(0)).ok();
    let Some(new_slot_barber) = new_slot_barber else { return HttpResponse::Conflict().json(json!({"error":"Slot unavailable"})); };
    if new_slot_barber != barber_id { return HttpResponse::BadRequest().json(json!({"error":"Can only reschedule within the same barber"})); }
    conn.execute("UPDATE bookings SET slot_id = ?1, reminder_sent = 0 WHERE id = ?2", params![body.slot_id, id]).unwrap();
    conn.execute("UPDATE slots SET is_available = 0 WHERE id = ?1", params![body.slot_id]).unwrap();
    conn.execute("UPDATE slots SET is_available = 1 WHERE id = ?1", params![old_slot_id]).unwrap();
    HttpResponse::Ok().json(json!({"ok": true}))
}

#[delete("/api/bookings/{id}")]
async fn cancel_booking(path: Path<String>, db: Data<Db>, req: HttpRequest, cfg: Data<AppConfig>) -> impl Responder {
    if let Err(resp) = require_csrf(&req, &db) { return resp; }
    let Some(claims) = jwt_from_req(&req, &cfg.jwt_secret) else { return HttpResponse::Unauthorized().json(json!({"error":"Login required"})); };
    let id = path.into_inner();
    let conn = db.lock().unwrap();
    let booking: Option<(String, String)> = conn.query_row("SELECT slot_id, user_id FROM bookings WHERE id = ?1", [id.clone()], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))).ok();
    let Some((slot_id, user_id)) = booking else { return HttpResponse::NotFound().json(json!({"error":"Booking not found"})); };
    if user_id != claims.sub { return HttpResponse::Forbidden().json(json!({"error":"Not your booking"})); }
    conn.execute("DELETE FROM bookings WHERE id = ?1", params![id]).unwrap();
    conn.execute("UPDATE slots SET is_available = 1 WHERE id = ?1", params![slot_id]).unwrap();
    let waitlist: Option<String> = conn.query_row("SELECT id FROM waitlist WHERE slot_id = ?1 ORDER BY joined_at ASC LIMIT 1", [slot_id.clone()], |row| row.get(0)).ok();
    if let Some(wait_id) = waitlist {
        let wait_user: Option<String> = conn.query_row("SELECT user_id FROM waitlist WHERE id = ?1", [wait_id.clone()], |row| row.get(0)).ok();
        if let Some(wait_user_id) = wait_user {
            conn.execute("DELETE FROM waitlist WHERE id = ?1", params![wait_id]).unwrap();
            let new_booking_id = Uuid::new_v4().to_string();
            let barber_id: String = conn.query_row("SELECT barber_id FROM slots WHERE id = ?1", [slot_id.clone()], |row| row.get(0)).unwrap_or_default();
            conn.execute("INSERT INTO bookings (id, user_id, barber_id, slot_id, service_name, status, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)", params![new_booking_id, wait_user_id, barber_id, slot_id.clone(), "Auto-filled", "confirmed", Utc::now().to_rfc3339()]).unwrap();
            conn.execute("UPDATE slots SET is_available = 0 WHERE id = ?1", params![slot_id.clone()]).unwrap();
            let contact: Option<(String, Option<String>)> = conn.query_row("SELECT phone, push_subscription FROM users WHERE id = ?1", [wait_user_id.clone()], |row| Ok((row.get(0)?, row.get(1)?))).ok();
            let slot_start: String = conn.query_row("SELECT start_time FROM slots WHERE id = ?1", [slot_id.clone()], |row| row.get(0)).unwrap_or_default();
            drop(conn);
            if let Some((phone, push_sub)) = contact {
                send_mail(&cfg, &format!("{}@clipvue.com", phone), "You're booked! (waitlist auto-fill)", &format!("A spot opened up and you were automatically booked for {slot_start}.")).await;
                if let Some(sub) = push_sub { if !sub.is_empty() { send_push(&cfg, &sub, "7gozati", "A spot opened up \u{2014} you're booked!").await; } }
            }
            return HttpResponse::Ok().json(json!({"ok": true}));
        }
    }
    HttpResponse::Ok().json(json!({"ok": true}))
}

const WAITLIST_MAX: i64 = 2;

#[post("/api/waitlist")]
async fn join_waitlist(body: Json<WaitlistBody>, db: Data<Db>, req: HttpRequest, cfg: Data<AppConfig>) -> impl Responder {
    if let Err(resp) = require_csrf(&req, &db) { return resp; }
    let Some(claims) = jwt_from_req(&req, &cfg.jwt_secret) else { return HttpResponse::Unauthorized().json(json!({"error":"Login required"})); };
    let conn = db.lock().unwrap();
    // Can't wait for a slot while already holding a confirmed booking.
    let has_booking: i64 = conn.query_row("SELECT COUNT(*) FROM bookings WHERE user_id = ?1 AND status = 'confirmed'", [claims.sub.clone()], |row| row.get(0)).unwrap_or(0);
    if has_booking > 0 { return HttpResponse::Conflict().json(json!({"error":"You already have a booking — cancel it before joining a waitlist"})); }
    // Only one waitlist spot per customer at a time.
    let mine: i64 = conn.query_row("SELECT COUNT(*) FROM waitlist WHERE user_id = ?1", [claims.sub.clone()], |row| row.get(0)).unwrap_or(0);
    if mine > 0 { return HttpResponse::Conflict().json(json!({"error":"You're already on a waitlist"})); }
    // Only taken slots have a waitlist; an open slot should just be booked.
    match conn.query_row("SELECT is_available FROM slots WHERE id = ?1", [body.slot_id.clone()], |row| row.get::<_, i64>(0)).ok() {
        None => return HttpResponse::NotFound().json(json!({"error":"Slot not found"})),
        Some(1) => return HttpResponse::BadRequest().json(json!({"error":"This slot is open — just book it"})),
        _ => {}
    }
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM waitlist WHERE slot_id = ?1", [body.slot_id.clone()], |row| row.get(0)).unwrap_or(0);
    if count >= WAITLIST_MAX { return HttpResponse::Conflict().json(json!({"error":"Waitlist is full (max 2)"})); }
    let id = Uuid::new_v4().to_string();
    match conn.execute("INSERT INTO waitlist (id, user_id, slot_id, joined_at) VALUES (?1, ?2, ?3, ?4)", params![id, claims.sub, body.slot_id, Utc::now().to_rfc3339()]) {
        Ok(_) => HttpResponse::Ok().json(json!({"ok": true})),
        Err(e) => { if e.to_string().contains("UNIQUE") { HttpResponse::Conflict().json(json!({"error":"Already on waitlist"})) } else { HttpResponse::InternalServerError().finish() } }
    }
}

#[delete("/api/waitlist/{slot_id}")]
async fn leave_waitlist(path: Path<String>, db: Data<Db>, req: HttpRequest, cfg: Data<AppConfig>) -> impl Responder {
    if let Err(resp) = require_csrf(&req, &db) { return resp; }
    let Some(claims) = jwt_from_req(&req, &cfg.jwt_secret) else { return HttpResponse::Unauthorized().json(json!({"error":"Login required"})); };
    let slot_id = path.into_inner();
    let conn = db.lock().unwrap();
    conn.execute("DELETE FROM waitlist WHERE user_id = ?1 AND slot_id = ?2", params![claims.sub, slot_id]).unwrap();
    HttpResponse::Ok().json(json!({"ok": true}))
}

#[get("/api/bookings")]
async fn public_bookings(db: Data<Db>) -> impl Responder {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare("SELECT b.id, b.user_id, b.barber_id, b.slot_id, b.service_name, b.selfie_base64, b.status, b.created_at, u.name, br.name, s.start_time FROM bookings b JOIN users u ON u.id = b.user_id JOIN barbers br ON br.id = b.barber_id JOIN slots s ON s.id = b.slot_id ORDER BY s.start_time ASC").unwrap();
    let bookings = stmt.query_map([], |row| Ok(BookingRow { id: row.get(0)?, user_id: row.get(1)?, barber_id: row.get(2)?, slot_id: row.get(3)?, service_name: row.get(4)?, selfie_base64: row.get(5)?, status: row.get(6)?, created_at: row.get(7)?, user_name: row.get(8).ok(), barber_name: row.get(9).ok(), slot_start: row.get(10).ok() })).unwrap().filter_map(|v| v.ok()).collect::<Vec<_>>();
    HttpResponse::Ok().json(json!({"bookings": bookings}))
}

#[get("/api/user/bookings")]
async fn user_bookings(db: Data<Db>, req: HttpRequest, cfg: Data<AppConfig>) -> impl Responder {
    let Some(claims) = jwt_from_req(&req, &cfg.jwt_secret) else { return HttpResponse::Unauthorized().json(json!({"error":"Login required"})); };
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare("SELECT b.id, b.user_id, b.barber_id, b.slot_id, b.service_name, b.selfie_base64, b.status, b.created_at, br.name, s.start_time FROM bookings b JOIN barbers br ON br.id = b.barber_id JOIN slots s ON s.id = b.slot_id WHERE b.user_id = ?1 ORDER BY s.start_time ASC").unwrap();
    let bookings = stmt.query_map([claims.sub.clone()], |row| Ok(BookingRow { id: row.get(0)?, user_id: row.get(1)?, barber_id: row.get(2)?, slot_id: row.get(3)?, service_name: row.get(4)?, selfie_base64: row.get(5)?, status: row.get(6)?, created_at: row.get(7)?, user_name: None, barber_name: row.get(8).ok(), slot_start: row.get(9).ok() })).unwrap().filter_map(|v| v.ok()).collect::<Vec<_>>();
    // Slot ids this customer is currently waitlisted for, so the UI can enforce
    // the "booking XOR waitlist" rule client-side too.
    let waitlist: Vec<String> = conn.prepare("SELECT slot_id FROM waitlist WHERE user_id = ?1").unwrap().query_map([claims.sub], |row| row.get(0)).unwrap().filter_map(|v| v.ok()).collect();
    HttpResponse::Ok().json(json!({"bookings": bookings, "waitlist": waitlist}))
}

#[get("/api/user/gdpr/export")]
async fn gdpr_export(db: Data<Db>, req: HttpRequest, cfg: Data<AppConfig>) -> impl Responder {
    let Some(claims) = jwt_from_req(&req, &cfg.jwt_secret) else { return HttpResponse::Unauthorized().json(json!({"error":"Login required"})); };
    let conn = db.lock().unwrap();
    let user: Option<UserRow> = conn.query_row("SELECT id, name, phone, timezone, gdpr_consent, created_at FROM users WHERE id = ?1", [claims.sub.clone()], |row| Ok(UserRow { id: row.get(0)?, name: row.get(1)?, phone: row.get(2)?, timezone: row.get(3)?, gdpr_consent: row.get(4)?, created_at: row.get(5)? })).ok();
    let bookings: Vec<BookingRow> = conn.prepare("SELECT b.id, b.user_id, b.barber_id, b.slot_id, b.service_name, b.selfie_base64, b.status, b.created_at, br.name, s.start_time FROM bookings b JOIN barbers br ON br.id = b.barber_id JOIN slots s ON s.id = b.slot_id WHERE b.user_id = ?1").unwrap().query_map([claims.sub], |row| Ok(BookingRow { id: row.get(0)?, user_id: row.get(1)?, barber_id: row.get(2)?, slot_id: row.get(3)?, service_name: row.get(4)?, selfie_base64: row.get(5)?, status: row.get(6)?, created_at: row.get(7)?, user_name: None, barber_name: row.get(8).ok(), slot_start: row.get(9).ok() })).unwrap().filter_map(|v| v.ok()).collect();
    HttpResponse::Ok().insert_header((header::CONTENT_DISPOSITION, "attachment; filename=\"clipvue-my-data.json\"")).json(json!({"user": user, "bookings": bookings}))
}

#[delete("/api/user/gdpr/delete")]
async fn gdpr_delete(db: Data<Db>, req: HttpRequest, cfg: Data<AppConfig>) -> impl Responder {
    if let Err(resp) = require_csrf(&req, &db) { return resp; }
    let Some(claims) = jwt_from_req(&req, &cfg.jwt_secret) else { return HttpResponse::Unauthorized().json(json!({"error":"Login required"})); };
    let conn = db.lock().unwrap();
    conn.execute("DELETE FROM users WHERE id = ?1", [claims.sub]).unwrap();
    let cookie = Cookie::build("token", "").path("/").http_only(true).same_site(SameSite::Strict).max_age(CookieDuration::seconds(0)).finish();
    HttpResponse::Ok().cookie(cookie).json(json!({"ok": true}))
}

#[get("/api/push/vapid-public-key")]
async fn vapid_public_key(cfg: Data<AppConfig>) -> impl Responder {
    HttpResponse::Ok().json(json!({"publicKey": cfg.vapid_public_key}))
}

#[post("/api/push/subscribe")]
async fn push_subscribe(body: Json<PushSubBody>, db: Data<Db>, req: HttpRequest, cfg: Data<AppConfig>) -> impl Responder {
    if let Err(resp) = require_csrf(&req, &db) { return resp; }
    let Some(claims) = jwt_from_req(&req, &cfg.jwt_secret) else { return HttpResponse::Unauthorized().json(json!({"error":"Login required"})); };
    let conn = db.lock().unwrap();
    conn.execute("UPDATE users SET push_subscription = ?1 WHERE id = ?2", params![body.subscription.to_string(), claims.sub]).unwrap();
    HttpResponse::Ok().json(json!({"ok": true}))
}

#[post("/api/analytics/pageview")]
async fn analytics_pageview(body: Json<AnalyticsBody>, db: Data<Db>, req: HttpRequest) -> impl Responder {
    let conn = db.lock().unwrap();
    let ip = client_ip(&req);
    conn.execute("INSERT INTO analytics (path, ip, user_agent, created_at) VALUES (?1, ?2, ?3, ?4)", params![sanitise(&body.path), ip, req.headers().get("user-agent").and_then(|h| h.to_str().ok()).unwrap_or_default(), Utc::now().to_rfc3339()]).unwrap();
    HttpResponse::Ok().json(json!({"ok": true}))
}

/// Serves the SPA shell with a fresh per-request CSP nonce injected into the inline <script> tag,
/// so the Content-Security-Policy can use 'nonce-...' instead of 'unsafe-inline'.
async fn serve_index() -> impl Responder {
    let nonce = gen_csrf();
    let html = match std::fs::read_to_string("static/index.html") {
        Ok(h) => h,
        Err(_) => return HttpResponse::InternalServerError().body("index missing"),
    };
    let html = html.replacen("<script>", &format!("<script nonce=\"{nonce}\">"), 1);
    let csp = format!("default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; manifest-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'");
    HttpResponse::Ok()
        .insert_header((header::CONTENT_TYPE, "text/html; charset=utf-8"))
        .insert_header((header::CONTENT_SECURITY_POLICY, csp))
        .body(html)
}

fn build_headers(dev_mode: bool) -> middleware::DefaultHeaders {
    let mut h = middleware::DefaultHeaders::new().add((header::CONTENT_SECURITY_POLICY, "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"));
    if !dev_mode {
        h = h.add((header::STRICT_TRANSPORT_SECURITY, "max-age=31536000; includeSubDomains"));
    }
    h
}

async fn send_mail(cfg: &AppConfig, to: &str, subject: &str, body: &str) {
    if cfg.smtp_host.is_empty() { return; }
    let Ok(mailbox) = to.parse() else { return; };
    let Ok(from) = cfg.smtp_from.parse() else { return; };
    let Ok(email) = Message::builder().from(from).to(mailbox).subject(subject).header(ContentType::TEXT_PLAIN).body(body.to_string()) else { return; };
    let Ok(builder) = AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.smtp_host) else { return; };
    let mailer = builder.port(cfg.smtp_port).credentials(Credentials::new(cfg.smtp_user.clone(), cfg.smtp_pass.clone())).build();
    if let Err(e) = mailer.send(email).await { error!("smtp error: {e}"); }
}

fn endpoint_origin(endpoint: &str) -> String {
    if let Some(scheme_end) = endpoint.find("://") {
        let after = &endpoint[scheme_end + 3..];
        let host_end = after.find('/').unwrap_or(after.len());
        format!("{}{}", &endpoint[..scheme_end + 3], &after[..host_end])
    } else {
        endpoint.to_string()
    }
}

/// Builds a VAPID (RFC8292) Authorization JWT, signed with our ES256 private key.
fn vapid_jwt(cfg: &AppConfig, aud: &str) -> Option<String> {
    let priv_bytes = B64URL.decode(&cfg.vapid_private_key).ok()?;
    let signing_key = SigningKey::from_slice(&priv_bytes).ok()?;
    let header = json!({"typ":"JWT","alg":"ES256"}).to_string();
    let exp = (Utc::now() + chrono::Duration::hours(12)).timestamp();
    let payload = json!({"aud": aud, "exp": exp, "sub": format!("mailto:{}", cfg.smtp_from)}).to_string();
    let signing_input = format!("{}.{}", B64URL.encode(header), B64URL.encode(payload));
    let signature: Signature = signing_key.sign(signing_input.as_bytes());
    Some(format!("{signing_input}.{}", B64URL.encode(signature.to_bytes())))
}

/// Encrypts a push payload per RFC8291 (aes128gcm). Returns (ciphertext, salt16, ephemeral_pubkey65).
fn encrypt_push_payload(client_pubkey_b64: &str, auth_secret_b64: &str, plaintext: &[u8]) -> Option<(Vec<u8>, [u8; 16], [u8; 65])> {
    let client_pub_bytes = B64URL.decode(client_pubkey_b64).ok()?;
    let auth_secret = B64URL.decode(auth_secret_b64).ok()?;
    let client_public = PublicKey::from_sec1_bytes(&client_pub_bytes).ok()?;
    let ephemeral_secret = SecretKey::random(&mut rand::rngs::OsRng);
    let ephemeral_public = ephemeral_secret.public_key();
    let ephemeral_pub_bytes: [u8; 65] = {
        let p = ephemeral_public.to_encoded_point(false);
        let mut arr = [0u8; 65];
        arr.copy_from_slice(p.as_bytes());
        arr
    };
    let shared = p256::ecdh::diffie_hellman(ephemeral_secret.to_nonzero_scalar(), client_public.as_affine());
    let ecdh_secret = shared.raw_secret_bytes();

    let mut key_info = Vec::from(&b"WebPush: info\0"[..]);
    key_info.extend_from_slice(&client_pub_bytes);
    key_info.extend_from_slice(&ephemeral_pub_bytes);
    let prk_key = Hkdf::<Sha256>::new(Some(&auth_secret), ecdh_secret.as_slice());
    let mut ikm = [0u8; 32];
    prk_key.expand(&key_info, &mut ikm).ok()?;

    let mut salt = [0u8; 16];
    rand::thread_rng().fill(&mut salt);
    let prk2 = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut cek = [0u8; 16];
    prk2.expand(b"Content-Encoding: aes128gcm\0", &mut cek).ok()?;
    let mut nonce_bytes = [0u8; 12];
    prk2.expand(b"Content-Encoding: nonce\0", &mut nonce_bytes).ok()?;

    let cipher = Aes128Gcm::new_from_slice(&cek).ok()?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let mut padded = plaintext.to_vec();
    padded.push(0x02); // last-record delimiter, single record
    let ciphertext = cipher.encrypt(nonce, padded.as_slice()).ok()?;

    Some((ciphertext, salt, ephemeral_pub_bytes))
}

/// Sends a real encrypted Web Push notification (RFC8291 + RFC8292 VAPID).
/// Best-effort: failures are logged, not propagated, since push is a non-critical enhancement.
async fn send_push(cfg: &AppConfig, sub_json: &str, title: &str, body: &str) {
    if cfg.vapid_private_key.is_empty() || cfg.vapid_public_key.is_empty() { return; }
    let Ok(subscription) = serde_json::from_str::<serde_json::Value>(sub_json) else { return; };
    let endpoint = subscription.get("endpoint").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    let Some(keys) = subscription.get("keys") else { return; };
    let p256dh = keys.get("p256dh").and_then(|v| v.as_str()).unwrap_or_default();
    let auth = keys.get("auth").and_then(|v| v.as_str()).unwrap_or_default();
    if endpoint.is_empty() || p256dh.is_empty() || auth.is_empty() { return; }
    let payload = json!({"title": title, "body": body, "icon": "/icon.png"}).to_string();
    let Some((ciphertext, salt, ephemeral_pub)) = encrypt_push_payload(p256dh, auth, payload.as_bytes()) else { error!("push: payload encryption failed"); return; };
    let mut wire_body = Vec::with_capacity(16 + 4 + 1 + 65 + ciphertext.len());
    wire_body.extend_from_slice(&salt);
    wire_body.extend_from_slice(&4096u32.to_be_bytes());
    wire_body.push(65u8);
    wire_body.extend_from_slice(&ephemeral_pub);
    wire_body.extend_from_slice(&ciphertext);
    let aud = endpoint_origin(&endpoint);
    let Some(jwt) = vapid_jwt(cfg, &aud) else { error!("push: vapid jwt failed"); return; };
    let auth_header = format!("vapid t={jwt}, k={}", cfg.vapid_public_key);
    let client = reqwest::Client::new();
    let res = client.post(&endpoint)
        .header("Content-Encoding", "aes128gcm")
        .header("Content-Type", "application/octet-stream")
        .header("TTL", "60")
        .header("Authorization", auth_header)
        .body(wire_body)
        .send().await;
    match res {
        Ok(r) if !r.status().is_success() => error!("push: endpoint returned {}", r.status()),
        Err(e) => error!("push error: {e}"),
        _ => {}
    }
}

async fn reminder_loop(db: Data<Db>, cfg: Data<AppConfig>) {
    let mut ticker = interval(Duration::from_secs(60));
    loop {
        ticker.tick().await;
        let now = Utc::now();
        let rows = {
            let conn = db.lock().unwrap();
            let mut stmt = conn.prepare("SELECT b.id, s.start_time, u.name, u.phone, u.push_subscription FROM bookings b JOIN slots s ON s.id = b.slot_id JOIN users u ON u.id = b.user_id WHERE b.status = 'confirmed' AND b.reminder_sent = 0").unwrap();
            stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, Option<String>>(4)?))).unwrap().filter_map(|v| v.ok()).collect::<Vec<_>>()
        };
        for (booking_id, slot_start, user_name, phone, push_sub) in rows {
            if let Ok(slot_dt) = DateTime::parse_from_rfc3339(&slot_start) {
                let diff = slot_dt.with_timezone(&Utc) - now;
                if diff.num_seconds() > 0 && diff.num_seconds() <= 3600 {
                    send_mail(&cfg, &format!("{}@clipvue.com", phone), "7gozati reminder", &format!("Hello {user_name}, your appointment starts in under an hour.")).await;
                    if let Some(sub) = push_sub { if !sub.is_empty() { send_push(&cfg, &sub, "7gozati reminder", "Your appointment starts in under an hour.").await; } }
                    let conn = db.lock().unwrap();
                    conn.execute("UPDATE bookings SET reminder_sent = 1 WHERE id = ?1", params![booking_id]).unwrap();
                }
            }
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    // Production safety: never boot a public instance with the built-in dev defaults.
    let is_prod = !std::env::var("DEV_MODE").map(|v| v == "true" || v == "1").unwrap_or(true);
    if is_prod {
        if std::env::var("JWT_SECRET").map(|v| v.trim().is_empty()).unwrap_or(true) {
            panic!("Refusing to start: set a strong JWT_SECRET when DEV_MODE=false (e.g. `fly secrets set JWT_SECRET=...`).");
        }
        if std::env::var("ADMIN_PASS").map(|v| v.trim().is_empty() || v == "admin123").unwrap_or(true) {
            panic!("Refusing to start: set a non-default ADMIN_PASS when DEV_MODE=false (e.g. `fly secrets set ADMIN_PASS=...`).");
        }
    }

    let db_path = std::env::var("DATABASE_URL").unwrap_or_else(|_| "clipvue.db".to_string());
    let conn = init_db(&db_path).expect("db init failed");
    let mut cfg_val = AppConfig::from_env();
    let (vapid_priv, vapid_pub) = ensure_vapid_keys(&conn, &cfg_val.vapid_private_key, &cfg_val.vapid_public_key);
    cfg_val.vapid_private_key = vapid_priv;
    cfg_val.vapid_public_key = vapid_pub;
    let dev_mode = cfg_val.dev_mode;

    let db = Data::new(Arc::new(Mutex::new(conn)));
    let cfg = Data::new(cfg_val);
    let rate_limiter = Data::new(Arc::new(Mutex::new(HashMap::<String, Vec<Instant>>::new())));

    // Global anti-abuse throttle. In actix-governor the period is the interval to replenish ONE
    // request slot, so per_millisecond(100) = ~10 req/s sustained (~600/min) with a 200-request
    // burst. This is generous enough for the SPA's per-page request fan-out while still capping
    // floods. (Brute-force on auth is handled separately by the 5/min limiter on login/signup.)
    let governor_conf = GovernorConfigBuilder::default().per_millisecond(100).burst_size(200).finish().unwrap();
    let db_for_task = db.clone();
    let cfg_for_task = cfg.clone();
    tokio::spawn(async move { reminder_loop(db_for_task, cfg_for_task).await; });

    info!("starting server on 0.0.0.0:8080");
    HttpServer::new(move || {
        App::new()
            .app_data(db.clone())
            .app_data(cfg.clone())
            .app_data(rate_limiter.clone())
            .wrap(Cors::permissive())
            .wrap(build_headers(dev_mode))
            .wrap(Governor::new(&governor_conf))
            .wrap(middleware::Logger::default())
            .route("/", web::get().to(serve_index))
            .route("/index.html", web::get().to(serve_index))
            .service(web::resource("/api/csrf-token").route(web::get().to(csrf_token)))
            .service(signup)
            .service(login)
            .service(logout)
            .service(me)
            .service(admin_login)
            .service(admin_logout)
            .service(admin_me)
            .service(admin_dashboard)
            .service(admin_bookings)
            .service(update_admin_booking)
            .service(delete_admin_booking)
            .service(create_barber)
            .service(delete_barber)
            .service(create_slots)
            .service(admin_list_slots)
            .service(update_slot)
            .service(delete_slot)
            .service(export_csv)
            .service(list_barbers)
            .service(list_slots)
            .service(create_booking)
            .service(reschedule_booking)
            .service(cancel_booking)
            .service(join_waitlist)
            .service(leave_waitlist)
            .service(public_bookings)
            .service(user_bookings)
            .service(gdpr_export)
            .service(gdpr_delete)
            .service(vapid_public_key)
            .service(push_subscribe)
            .service(analytics_pageview)
            .service(Files::new("/", "static"))
    })
    .bind(("0.0.0.0", 8080))?
    .run().await
}

use base64::{
    Engine,
    prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD},
};
use libc::{c_char, c_int, c_void};
use log::{LevelFilter, debug, info, trace, warn};
use p256::ecdsa::signature::Verifier;
use p256::pkcs8::DecodePublicKey;
use pam_sys::{
    PamConversation, PamHandle, PamItemType, PamMessage, PamMessageStyle, PamResponse,
    PamReturnCode,
};
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
#[cfg(feature = "debug")]
use simplelog::{ColorChoice, TermLogger, TerminalMode};
use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::io::{self, ErrorKind, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::slice::from_raw_parts;
use std::str::{FromStr, Utf8Error};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
#[cfg(not(feature = "debug"))]
use syslog::Facility;

/// One file per Unix user (`PAM_USER`), root:root 0600
const CONFIG_DIR: &str = "/etc/pam_web";

/// How long the user has to answer. The server gives up first (web/app/api/endpoints/authorization.ts)
const TIMEOUT: Duration = Duration::from_secs(60);

/// # Safety
/// Called by libpam: `pamh` must be a valid handle, `argv` must hold `argc` valid C strings (or be null).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    // Convert argv to Vec<String>
    let argv = match convert_argv(argc, argv) {
        Ok(argv) => argv,
        Err(err) => {
            eprintln!("Failed to parse argc/argv");
            eprintln!("Error : {err:?}");
            return PamReturnCode::AUTH_ERR as c_int;
        }
    };

    init_logger(argv.get(1));
    trace!("Authorize PAM request through web");
    debug!("argv : {argv:?}");

    // Retrieve URL from arguments
    let url = match argv.first() {
        Some(url) => {
            debug!("URL : {url}");
            url.clone()
        }
        None => {
            warn!("No URL given in parameter used (usage : pam_web URL [LOG_LEVEL])");
            return PamReturnCode::AUTH_ERR as c_int;
        }
    };

    let Some(pamh) = (unsafe { pamh.as_ref() }) else {
        warn!("Null PAM handle");
        return PamReturnCode::AUTH_ERR as c_int;
    };
    let Some(pam_user) = get_user(pamh) else {
        warn!("Failed to get PAM user");
        return PamReturnCode::AUTH_ERR as c_int;
    };

    // Per-user config : not enrolled = let the rest of the stack decide
    let Some(path) = config_path(Path::new(CONFIG_DIR), &pam_user) else {
        warn!("Invalid PAM user name '{pam_user}'");
        return PamReturnCode::AUTH_ERR as c_int;
    };
    let config = match read_config(&path, 0) {
        Ok(config) => config,
        Err(ConfigError::Missing) => {
            debug!("No config for {pam_user}, ignoring");
            return PamReturnCode::IGNORE as c_int;
        }
        Err(err) => {
            warn!("Rejecting {} : {err:?}", path.display());
            return PamReturnCode::AUTH_ERR as c_int;
        }
    };

    // Only a passkey signature approves : without keys, nothing can
    if config.keys.is_empty() {
        warn!("No 'key' line in {}", path.display());
        return PamReturnCode::AUTH_ERR as c_int;
    }
    debug!("{} passkey(s) for {pam_user}", config.keys.len());

    // The passkeys are bound to the server's site : that's what the signature must be for
    let Some(site) = Site::from_url(&url) else {
        warn!("Invalid URL '{url}'");
        return PamReturnCode::AUTH_ERR as c_int;
    };

    let request = match new_request(pamh, &config, &pam_user) {
        Ok(request) => request,
        Err(err) => {
            warn!("Failed to build the request : {err:?}");
            return PamReturnCode::AUTH_ERR as c_int;
        }
    };
    let code = &request.code;
    pam_info(
        pamh,
        &if request.typed {
            format!("pam_web : approve in your browser and type the code {code}")
        } else {
            format!("pam_web : approve in your browser, code {code}")
        },
    );

    // Access API for authorization, then check the passkey signature
    let uid = unsafe { libc::getuid() };
    let authorized = match authorize(url, request.body.clone()) {
        None => {
            info!("Blocked for {pam_user} (uid {uid})");
            false
        }
        Some(assertion) => match verify(
            &assertion,
            &site,
            &challenge(&request.body, code),
            &config.keys,
        ) {
            Ok(key) => {
                info!(
                    "Authorized for {pam_user} (uid {uid}) by key '{}'",
                    key.name
                );
                true
            }
            Err(err) => {
                warn!("Rejected answer for {pam_user} (uid {uid}) : {err}");
                false
            }
        },
    };
    if authorized {
        PamReturnCode::SUCCESS as c_int
    } else {
        PamReturnCode::AUTH_ERR as c_int
    }
}

fn convert_argv(argc: c_int, argv: *const *const c_char) -> Result<Vec<String>, Utf8Error> {
    // from_raw_parts is UB on a null pointer, even with length 0
    if argc <= 0 || argv.is_null() {
        return Ok(Vec::new());
    }
    // PAM guarantees argc valid C strings in argv
    unsafe { from_raw_parts(argv, argc as usize) }
        .iter()
        .map(|arg| {
            unsafe { CStr::from_ptr(*arg) }
                .to_str()
                .map(ToString::to_string)
        })
        .collect()
}

#[derive(Debug, PartialEq)]
struct Config {
    /// The web (Authelia) user who approves
    user: String,
    /// Proves to the server we may create requests for `user` (shown on the page)
    token: String,
    /// Passkeys allowed to approve
    keys: Vec<Key>,
}

/// From a `key <alg> <base64 SPKI> [name]` line, as shown by the registration page
#[derive(Debug, PartialEq)]
struct Key {
    name: String,
    public: PublicKey,
}

#[derive(Debug, PartialEq)]
enum PublicKey {
    Es256(p256::PublicKey),
    Ed25519(ed25519_dalek::VerifyingKey),
}

fn parse_key(value: &str) -> Result<Key, String> {
    let mut parts = value.split_whitespace();
    let (Some(alg), Some(spki)) = (parts.next(), parts.next()) else {
        return Err("Expected 'key <alg> <base64 SPKI> [name]'".into());
    };
    let name = parts.collect::<Vec<_>>().join(" ");
    let der = BASE64_STANDARD
        .decode(spki)
        .map_err(|err| format!("Invalid base64 : {err}"))?;
    let public = match alg {
        "es256" => p256::PublicKey::from_public_key_der(&der).map(PublicKey::Es256),
        "ed25519" => ed25519_dalek::VerifyingKey::from_public_key_der(&der).map(PublicKey::Ed25519),
        _ => return Err(format!("Unknown algorithm '{alg}'")),
    }
    .map_err(|err| format!("Invalid {alg} key : {err}"))?;
    Ok(Key { name, public })
}

#[derive(Debug, PartialEq)]
enum ConfigError {
    Missing,
    /// Not owned by the expected uid, or accessible by group/others
    Insecure,
    Invalid(String),
}

/// `None` if the user name could escape `dir`
fn config_path(dir: &Path, user: &str) -> Option<PathBuf> {
    if user.is_empty() || user.starts_with('.') || user.contains('/') {
        return None;
    }
    Some(dir.join(user))
}

fn read_config(path: &Path, owner: u32) -> Result<Config, ConfigError> {
    let meta = match fs::metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == ErrorKind::NotFound => return Err(ConfigError::Missing),
        Err(err) => return Err(ConfigError::Invalid(err.to_string())),
    };
    if !meta.is_file() || meta.uid() != owner || meta.mode() & 0o077 != 0 {
        return Err(ConfigError::Insecure);
    }
    let content = fs::read_to_string(path).map_err(|err| ConfigError::Invalid(err.to_string()))?;

    let mut user = None;
    let mut keys = Vec::new();
    for line in content.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match line.split_once(char::is_whitespace) {
            Some(("user", value)) => user = Some(parse_user(value).map_err(ConfigError::Invalid)?),
            Some(("key", value)) => keys.push(parse_key(value).map_err(ConfigError::Invalid)?),
            _ => return Err(ConfigError::Invalid(format!("Unknown line '{line}'"))),
        }
    }
    let (user, token) = user.ok_or(ConfigError::Invalid("No 'user' line".into()))?;
    Ok(Config { user, token, keys })
}

/// `user <web user> <token>`, as shown by the page
fn parse_user(value: &str) -> Result<(String, String), String> {
    let mut parts = value.split_whitespace();
    match (parts.next(), parts.next(), parts.next()) {
        (Some(user), Some(token), None)
            if token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()) =>
        {
            Ok((user.to_string(), token.to_string()))
        }
        _ => Err("Expected 'user <web user> <64 hex token>'".into()),
    }
}

struct Request {
    /// Sent as is : the browser signs these exact bytes
    body: String,
    code: String,
    /// The code isn't in the body : the user types it in the browser
    typed: bool,
}

fn new_request(pamh: &PamHandle, config: &Config, pam_user: &str) -> io::Result<Request> {
    let code = format!("{:06}", u64::from_le_bytes(random()?) % 1_000_000);
    // ponytail: 1 in 3, a per-user setting if it's ever needed
    let typed = random::<1>()?[0] % 3 == 0;
    let nonce: String = random::<32>()?.iter().map(|b| format!("{b:02x}")).collect();
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut body = json!({
        "user": config.user,
        "token": config.token,
        "nonce": nonce,
        "ts": ts,
        "uid": unsafe { libc::getuid() },
        "pam_user": pam_user,
        "ruser": get_item(pamh, PamItemType::RUSER),
        "service": get_item(pamh, PamItemType::SERVICE),
        "tty": get_item(pamh, PamItemType::TTY),
        "rhost": get_item(pamh, PamItemType::RHOST),
        "cmdline": cmdline(),
        "hostname": hostname(),
    });
    if !typed {
        body["code"] = json!(code);
    }
    Ok(Request {
        body: body.to_string(),
        code,
        typed,
    })
}

/// What the passkey signs : SHA-256(body ‖ "\n" ‖ code ‖ "\nallow"), see web/app/helpers/passkey.ts
fn challenge(body: &str, code: &str) -> [u8; 32] {
    Sha256::digest(format!("{body}\n{code}\nallow")).into()
}

/// The WebAuthn relying party : the passkeys belong to this site
#[derive(Debug)]
struct Site {
    /// rpId, the host (pam.example.com)
    id: String,
    /// Where the browser was (https://pam.example.com)
    origin: String,
}

impl Site {
    fn from_url(url: &str) -> Option<Site> {
        let url = reqwest::Url::parse(url).ok()?;
        Some(Site {
            id: url.host_str()?.to_string(),
            origin: url.origin().ascii_serialization(),
        })
    }
}

/// navigator.credentials.get's answer, relayed by the server
#[derive(Debug)]
struct Assertion {
    authenticator_data: Vec<u8>,
    client_data_json: Vec<u8>,
    signature: Vec<u8>,
}

impl Assertion {
    fn from_json(json: &str) -> Option<Assertion> {
        let json: Value = serde_json::from_str(json).ok()?;
        let field = |name: &str| BASE64_STANDARD.decode(json[name].as_str()?).ok();
        Some(Assertion {
            authenticator_data: field("authenticator_data")?,
            client_data_json: field("client_data_json")?,
            signature: field("signature")?,
        })
    }
}

/// The key that signed `challenge` for `site`, with the user present and verified
fn verify<'k>(
    assertion: &Assertion,
    site: &Site,
    challenge: &[u8; 32],
    keys: &'k [Key],
) -> Result<&'k Key, String> {
    let client: Value = serde_json::from_slice(&assertion.client_data_json)
        .map_err(|err| format!("Invalid clientDataJSON : {err}"))?;
    if client["type"] != "webauthn.get" {
        return Err(format!("Wrong type {}", client["type"]));
    }
    if client["challenge"] != BASE64_URL_SAFE_NO_PAD.encode(challenge).as_str() {
        return Err("Wrong challenge : another request, or a wrong typed code".into());
    }
    if client["origin"] != site.origin.as_str() {
        return Err(format!("Wrong origin {}", client["origin"]));
    }
    if client["crossOrigin"] == true {
        return Err("Cross-origin".into());
    }

    let data = &assertion.authenticator_data;
    if data.len() < 37 {
        return Err("authenticatorData too short".into());
    }
    if data[..32] != Sha256::digest(&site.id)[..] {
        return Err("Signed for another site".into());
    }
    let flags = data[32];
    if flags & 0x01 == 0 {
        return Err("User not present".into());
    }
    if flags & 0x04 == 0 {
        return Err("User not verified".into());
    }

    let mut signed = data.clone();
    signed.extend(Sha256::digest(&assertion.client_data_json));
    let signature = &assertion.signature;
    keys.iter()
        .find(|key| match &key.public {
            PublicKey::Es256(public) => {
                p256::ecdsa::Signature::from_der(signature).is_ok_and(|s| {
                    p256::ecdsa::VerifyingKey::from(public)
                        .verify(&signed, &s)
                        .is_ok()
                })
            }
            PublicKey::Ed25519(public) => ed25519_dalek::Signature::from_slice(signature)
                .is_ok_and(|s| public.verify_strict(&signed, &s).is_ok()),
        })
        .ok_or("No key matches the signature".into())
}

fn random<const N: usize>() -> io::Result<[u8; N]> {
    let mut bytes = [0; N];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// The command being authorized : we run inside sudo/su, so it's our own command line
fn cmdline() -> Vec<String> {
    fs::read("/proc/self/cmdline")
        .unwrap_or_default()
        .split(|b| *b == 0)
        .filter(|arg| !arg.is_empty())
        .map(|arg| String::from_utf8_lossy(arg).into_owned())
        .collect()
}

fn hostname() -> String {
    let mut buf = [0u8; 256];
    if unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } != 0 {
        return String::new();
    }
    CStr::from_bytes_until_nul(&buf)
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn get_user(pamh: &PamHandle) -> Option<String> {
    let mut user: *const c_char = null();
    if pam_sys::get_user(pamh, &mut user, null()) != PamReturnCode::SUCCESS || user.is_null() {
        return None;
    }
    Some(
        unsafe { CStr::from_ptr(user) }
            .to_string_lossy()
            .into_owned(),
    )
}

fn get_item(pamh: &PamHandle, item: PamItemType) -> Option<String> {
    let mut value: *const c_void = null();
    if pam_sys::get_item(pamh, item, &mut value) != PamReturnCode::SUCCESS || value.is_null() {
        return None;
    }
    Some(
        unsafe { CStr::from_ptr(value.cast()) }
            .to_string_lossy()
            .into_owned(),
    )
}

/// Show `text` to the user (terminal for sudo/su), through the PAM conversation
fn pam_info(pamh: &PamHandle, text: &str) {
    let mut conv: *const c_void = null();
    if pam_sys::get_item(pamh, PamItemType::CONV, &mut conv) != PamReturnCode::SUCCESS {
        return;
    }
    let Some(conv) = (unsafe { conv.cast::<PamConversation>().as_ref() }) else {
        return;
    };
    let (Some(converse), Ok(text)) = (conv.conv, CString::new(text)) else {
        return;
    };

    let mut message = PamMessage {
        msg_style: PamMessageStyle::TEXT_INFO as c_int,
        msg: text.as_ptr(),
    };
    let mut messages: *mut PamMessage = &mut message;
    let mut response: *mut PamResponse = null_mut();
    converse(1, &mut messages, &mut response, conv.data_ptr);
    // The application allocates the responses, we free them
    if !response.is_null() {
        unsafe {
            libc::free((*response).resp.cast());
            libc::free(response.cast());
        }
    }
}

/// The server's answer, None if blocked, timed out or failed
fn authorize(url: String, body: String) -> Option<Assertion> {
    trace!("Send request to API");

    // Send request to server
    // No proxy from the environment : the answer is signed, but a proxy could still delay or drop it
    let client = match reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(TIMEOUT)
        .build()
    {
        Ok(client) => client,
        Err(err) => {
            warn!("Failed to create the HTTP client : {err:?}");
            return None;
        }
    };
    let request = client
        .post(url)
        .header("Content-Type", "application/json")
        .body(body)
        .send();
    let request = match request {
        Ok(r) => r,
        Err(err) => {
            warn!("Request to API failed");
            debug!("error : {err:?}");
            return None;
        }
    };

    // Check response status
    if request.status() != StatusCode::OK {
        warn!("API request rejected");
        debug!("Status : {}", request.status());
        return None;
    }

    // Retrieve and parse body to get authorization
    let body = match request.text() {
        Ok(body) => body,
        Err(err) => {
            warn!("Failed to parse body of answer");
            debug!("Error : {err:?}");
            return None;
        }
    };

    let assertion = Assertion::from_json(&body);
    if assertion.is_none() {
        warn!("Invalid body content");
        debug!("Body : {body}");
    }
    assertion
}

fn init_logger(argv: Option<&String>) {
    let (level, failed) = match argv {
        Some(l) => match LevelFilter::from_str(l) {
            Ok(l) => (l, None),
            Err(err) => (LevelFilter::Warn, Some(err)),
        },
        None => (LevelFilter::Warn, None),
    };

    #[cfg(feature = "debug")]
    TermLogger::init(
        level,
        Default::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap();

    #[cfg(not(feature = "debug"))]
    if let Err(err) = syslog::init(Facility::LOG_AUTHPRIV, level, Some("pam_web")) {
        eprintln!("Failed to init syslog");
        eprintln!("Error : {err:?}");
        eprintln!("Continuing web authentication");
        return;
    }

    if let Some(err) = failed {
        warn!("Failed to parse log level");
        warn!("Error : {err:?}");
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_setcred(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PamReturnCode::SUCCESS as i32
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::os::unix::fs::PermissionsExt;
    use std::thread;

    #[test]
    fn argv_null_or_empty() {
        assert_eq!(convert_argv(0, std::ptr::null()), Ok(vec![]));
        assert_eq!(convert_argv(3, std::ptr::null()), Ok(vec![]));
        assert_eq!(convert_argv(-1, std::ptr::null()), Ok(vec![]));
    }

    #[test]
    fn argv_converted() {
        let args = [
            CString::new("https://x").unwrap(),
            CString::new("debug").unwrap(),
        ];
        let ptrs: Vec<*const c_char> = args.iter().map(|a| a.as_ptr()).collect();
        assert_eq!(
            convert_argv(2, ptrs.as_ptr()),
            Ok(vec!["https://x".to_string(), "debug".to_string()])
        );
    }

    // openssl genpkey + openssl pkey -pubout -outform DER | base64
    const P256: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEODH6vwvuPAOqvQ+mvX9eOvEEr2z/Df9jgLNSEMMVaLnqcQsrtZvAeZ6TAmek+ZYcEb1M06y2ZaCxxgH7lP8PWg==";
    const ED25519: &str = "MCowBQYDK2VwAyEAf09nQxD5eeUx3oRmYZ+x/6FnMfs7fmFeNku9+OHjxLw=";

    #[test]
    fn key_lines() {
        assert!(parse_key(&format!("es256 {P256} name")).is_ok());
        assert!(parse_key(&format!("ed25519 {ED25519}")).is_ok());
        // Algorithm and key type must match
        assert!(parse_key(&format!("es256 {ED25519}")).is_err());
        assert!(parse_key(&format!("ed25519 {P256}")).is_err());
        assert!(parse_key(&format!("rs256 {P256}")).is_err());
        assert!(parse_key("es256 not-base64!").is_err());
        assert!(parse_key("es256").is_err());
        assert!(parse_key("").is_err());
    }

    #[test]
    fn user_lines() {
        let token = "7a7bd60797bcd90fc794b0a6e6fc36c6a78511f79ed4dd9246b9259f7c0c404e";
        assert_eq!(
            parse_user(&format!("alice {token}")),
            Ok(("alice".into(), token.into()))
        );
        // The old format (a UUID alone), a short or non-hex token, extra words
        assert!(parse_user("9181a851-bc57-4d07-bb44-e2602b96fd9f").is_err());
        assert!(parse_user("alice abc").is_err());
        assert!(parse_user(&format!("alice {}", "g".repeat(64))).is_err());
        assert!(parse_user(&format!("alice {token} extra")).is_err());
        assert!(parse_user("").is_err());
    }

    #[test]
    fn config_path_stays_in_dir() {
        let dir = Path::new("/etc/pam_web");
        assert_eq!(config_path(dir, "alice"), Some(dir.join("alice")));
        for user in ["", ".", "..", "../etc/shadow", "a/b", ".hidden"] {
            assert_eq!(config_path(dir, user), None, "{user}");
        }
    }

    /// Write `content` with `mode` in a fresh file, return its path
    fn config_file(name: &str, content: &str, mode: u32) -> PathBuf {
        let path = std::env::temp_dir().join(format!("pam_web_test_{}_{name}", std::process::id()));
        fs::write(&path, content).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[test]
    fn config_read() {
        let me = unsafe { libc::getuid() };
        let token = "7a7bd60797bcd90fc794b0a6e6fc36c6a78511f79ed4dd9246b9259f7c0c404e";
        let user_line = format!("alice {token}");

        let ok = config_file("ok", &format!("# comment\n\nuser {user_line}\n"), 0o600);
        assert_eq!(
            read_config(&ok, me),
            Ok(Config {
                user: "alice".into(),
                token: token.into(),
                keys: vec![]
            })
        );
        // Owned by someone else (root expected, we aren't)
        if me != 0 {
            assert_eq!(read_config(&ok, 0), Err(ConfigError::Insecure));
        }

        let readable = config_file("readable", &format!("user {user_line}\n"), 0o644);
        assert_eq!(read_config(&readable, me), Err(ConfigError::Insecure));

        let unknown = config_file("unknown", &format!("user {user_line}\nfoo bar\n"), 0o600);
        assert!(matches!(
            read_config(&unknown, me),
            Err(ConfigError::Invalid(_))
        ));

        let no_user = config_file("no_user", "# nothing\n", 0o600);
        assert!(matches!(
            read_config(&no_user, me),
            Err(ConfigError::Invalid(_))
        ));

        let keys = config_file(
            "keys",
            &format!(
                "user {user_line}\nkey es256 {P256} MacBook Touch ID\nkey ed25519 {ED25519}\n"
            ),
            0o600,
        );
        let config = read_config(&keys, me).unwrap();
        assert_eq!(config.keys.len(), 2);
        assert_eq!(config.keys[0].name, "MacBook Touch ID");
        assert!(matches!(config.keys[0].public, PublicKey::Es256(_)));
        assert_eq!(config.keys[1].name, "");
        assert!(matches!(config.keys[1].public, PublicKey::Ed25519(_)));

        let bad_key = config_file(
            "bad_key",
            &format!("user {user_line}\nkey es256 nope\n"),
            0o600,
        );
        assert!(matches!(
            read_config(&bad_key, me),
            Err(ConfigError::Invalid(_))
        ));

        let missing = std::env::temp_dir().join("pam_web_test_does_not_exist");
        assert_eq!(read_config(&missing, me), Err(ConfigError::Missing));

        for path in [ok, readable, unknown, no_user, keys, bad_key] {
            fs::remove_file(path).unwrap();
        }
    }

    /// Serve one canned HTTP response, return its URL
    fn serve(status: &str, body: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.read(&mut [0; 4096]);
            stream.write_all(response.as_bytes()).unwrap();
        });
        url
    }

    #[test]
    fn authorize_only_on_200_with_an_assertion() {
        let body = || "{}".to_string();
        let assertion =
            r#"{"authenticator_data": "YQ==", "client_data_json": "Yg==", "signature": "Yw=="}"#;
        let answer = authorize(serve("200 OK", assertion), body()).unwrap();
        assert_eq!(
            (
                answer.authenticator_data,
                answer.client_data_json,
                answer.signature
            ),
            (b"a".to_vec(), b"b".to_vec(), b"c".to_vec())
        );
        assert!(authorize(serve("403 Forbidden", ""), body()).is_none());
        assert!(authorize(serve("500 Internal Server Error", assertion), body()).is_none());
        // The old plain answer isn't enough anymore
        assert!(authorize(serve("200 OK", "OK"), body()).is_none());
        assert!(authorize(serve("200 OK", r#"{"signature": "Yw=="}"#), body()).is_none());
        assert!(authorize(serve("200 OK", ""), body()).is_none());
    }

    #[test]
    fn challenge_vector() {
        // Same vector as web/app/helpers/passkey.test.ts
        assert_eq!(
            BASE64_URL_SAFE_NO_PAD.encode(challenge(r#"{"a":1}"#, "123456")),
            "rzaEcLei7fhZ2JYuPdC_4qUdhHzwadv6vuTPYcXcsTE"
        );
    }

    #[test]
    fn site_from_url() {
        let site = Site::from_url("https://pam.example.com/api/authorization/request").unwrap();
        assert_eq!(
            (site.id.as_str(), site.origin.as_str()),
            ("pam.example.com", "https://pam.example.com")
        );
        let site = Site::from_url("http://server:5199/api/authorization/request").unwrap();
        assert_eq!(
            (site.id.as_str(), site.origin.as_str()),
            ("server", "http://server:5199")
        );
        assert!(Site::from_url("not a url").is_none());
    }

    /// A software passkey : what a browser + authenticator would answer
    struct Passkey {
        es256: p256::ecdsa::SigningKey,
        ed25519: ed25519_dalek::SigningKey,
    }

    impl Passkey {
        fn new(seed: u8) -> Passkey {
            Passkey {
                es256: p256::ecdsa::SigningKey::from_bytes(&[seed; 32].into()).unwrap(),
                ed25519: ed25519_dalek::SigningKey::from_bytes(&[seed; 32]),
            }
        }

        fn keys(&self) -> Vec<Key> {
            vec![
                Key {
                    name: "es256".into(),
                    public: PublicKey::Es256((*self.es256.verifying_key()).into()),
                },
                Key {
                    name: "ed25519".into(),
                    public: PublicKey::Ed25519(self.ed25519.verifying_key()),
                },
            ]
        }

        fn sign(&self, ed25519: bool, rp_id: &str, flags: u8, client: &Value) -> Assertion {
            let mut authenticator_data = Sha256::digest(rp_id).to_vec();
            authenticator_data.push(flags);
            authenticator_data.extend([0; 4]); // Counter, always 0 for synced passkeys
            let client_data_json = client.to_string().into_bytes();
            let mut signed = authenticator_data.clone();
            signed.extend(Sha256::digest(&client_data_json));
            let signature = if ed25519 {
                use ed25519_dalek::Signer;
                self.ed25519.sign(&signed).to_bytes().to_vec()
            } else {
                use p256::ecdsa::signature::Signer;
                let signature: p256::ecdsa::Signature = self.es256.sign(&signed);
                signature.to_der().as_bytes().to_vec()
            };
            Assertion {
                authenticator_data,
                client_data_json,
                signature,
            }
        }
    }

    #[test]
    fn verify_assertions() {
        let passkey = Passkey::new(1);
        let keys = passkey.keys();
        let site = Site::from_url("https://pam.example.com/api/authorization/request").unwrap();
        let challenge = challenge(r#"{"a":1}"#, "123456");
        let client = |challenge: &[u8; 32]| {
            json!({
                "type": "webauthn.get",
                "challenge": BASE64_URL_SAFE_NO_PAD.encode(challenge),
                "origin": "https://pam.example.com",
                "crossOrigin": false,
            })
        };
        let ok = client(&challenge);
        // User present + verified
        let flags = 0x05;

        for ed25519 in [false, true] {
            let assertion = passkey.sign(ed25519, "pam.example.com", flags, &ok);
            let key = verify(&assertion, &site, &challenge, &keys).unwrap();
            assert_eq!(key.name, if ed25519 { "ed25519" } else { "es256" });

            let rejected =
                |assertion: Assertion| verify(&assertion, &site, &challenge, &keys).unwrap_err();
            // Another request, or a wrong typed code
            let other = super::challenge(r#"{"a":1}"#, "654321");
            assert!(
                rejected(passkey.sign(ed25519, "pam.example.com", flags, &client(&other)))
                    .contains("challenge")
            );
            // Another site
            assert!(rejected(passkey.sign(ed25519, "evil.example", flags, &ok)).contains("site"));
            let mut evil = ok.clone();
            evil["origin"] = json!("https://evil.example");
            assert!(
                rejected(passkey.sign(ed25519, "pam.example.com", flags, &evil)).contains("origin")
            );
            let mut cross = ok.clone();
            cross["crossOrigin"] = json!(true);
            assert!(
                rejected(passkey.sign(ed25519, "pam.example.com", flags, &cross)).contains("Cross")
            );
            let mut create = ok.clone();
            create["type"] = json!("webauthn.create");
            assert!(
                rejected(passkey.sign(ed25519, "pam.example.com", flags, &create)).contains("type")
            );
            // Not present, not verified
            assert!(rejected(passkey.sign(ed25519, "pam.example.com", 0x04, &ok)).contains("present"));
            assert!(
                rejected(passkey.sign(ed25519, "pam.example.com", 0x01, &ok)).contains("verified")
            );
            // Another passkey
            assert!(
                rejected(Passkey::new(2).sign(ed25519, "pam.example.com", flags, &ok))
                    .contains("No key")
            );
            // One byte changed in the signed data or the signature
            let mut tampered = passkey.sign(ed25519, "pam.example.com", flags, &ok);
            tampered.authenticator_data[33] ^= 1;
            assert!(rejected(tampered).contains("No key"));
            let mut tampered = passkey.sign(ed25519, "pam.example.com", flags, &ok);
            let last = tampered.signature.len() - 1;
            tampered.signature[last] ^= 1;
            assert!(rejected(tampered).contains("No key"));
            // Not the key's own algorithm
            let only_other: Vec<Key> = passkey
                .keys()
                .into_iter()
                .filter(|k| (k.name == "ed25519") != ed25519)
                .collect();
            assert!(
                verify(
                    &passkey.sign(ed25519, "pam.example.com", flags, &ok),
                    &site,
                    &challenge,
                    &only_other
                )
                .is_err()
            );
        }
    }

    #[test]
    fn proxy_from_env_ignored() {
        // A proxy that isn't there : it would fail if used
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let proxy = format!("http://127.0.0.1:{port}");
        unsafe {
            std::env::set_var("HTTP_PROXY", &proxy);
            std::env::set_var("http_proxy", &proxy);
            std::env::set_var("ALL_PROXY", &proxy);
        }
        let assertion =
            r#"{"authenticator_data": "YQ==", "client_data_json": "Yg==", "signature": "Yw=="}"#;
        assert!(authorize(serve("200 OK", assertion), "{}".to_string()).is_some());
    }

    #[test]
    fn authorize_unreachable() {
        // Bind then drop: nothing listens on that port anymore
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        assert!(authorize(format!("http://127.0.0.1:{port}/"), "{}".to_string()).is_none());
    }
}

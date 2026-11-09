//! TeleAgent 桌面端**本机登录态**：定位数据目录、解密 safeStorage 凭据、
//! 读设备指纹与客户端版本，并解析网关 apiKey。
//!
//! ── 为什么不再让用户粘贴三条凭据 ──────────────────────────────
//! 老实现要求用户从客户端里手抄 `token` / `deviceId` / `installId`。这三条
//! 本来就存在客户端自己的数据目录里（加密的），手抄既麻烦又容易抄错 —— 抄错
//! 任何一个，上游只回一个笼统的 401。参考实现 `anbulang/opencode-teleagent-auth`
//! 改成运行时读盘 + 解密，本模块是同一套做法的 Rust 重写（协议见
//! https://github.com/anbulang/opencode-teleagent-auth 的 `docs/PROTOCOL.md`）。
//!
//! ── 文件布局（Windows 实测，客户端 3.0.0）────────────────────
//! ```text
//! %USERPROFILE%\.local\share\TeleAgent\
//! ├── Local State                       os_crypt.encrypted_key（DPAPI 包着的 AES 密钥）
//! ├── current-owner.json                当前账号指针 {ownerDir, userId, generation}
//! ├── instance-marker.json              客户端版本（运行中才有）
//! ├── updater.json                      lastVersion（兜底）
//! ├── app-auth\device-meta.json         { deviceId, installId }
//! └── users\<scope>\app-auth\token.json { version, encryptedToken, encrypted, scheme }
//! ```
//! `<scope>` 形如 `v1_public_<userId>`。
//!
//! ── 解密链（与仓库里 AutoClaw / 豆包工作用的同一条）──────────
//! ```text
//! Local State → os_crypt.encrypted_key → base64 → 去 5 字节 "DPAPI"
//!   → CryptUnprotectData → 32 字节 AES-256 密钥
//! token.json → encryptedToken → base64 → "v10" + 12 字节 nonce + 密文 + 16 字节 tag
//!   → AES-256-GCM → 明文 "<tenant>:<JWT>"
//! ```
//! 这几步**直接复用** `crate::crypto`（`os_crypt_aes_key` + `decrypt_os_crypt_blob`），
//! 不新造轮子。本机实测通过（2026-11-09，客户端 3.0.0）。
//!
//! ── 平台约束 ────────────────────────────────────────────────
//! DPAPI 只有 Windows 有。非 Windows 上本模块**直接返回错误**，让调用方回落到
//! 「手动粘贴三条凭据」那条路 —— 与 `doubaowork::cookies_db` 的取舍一致
//! （那边的原话：「DPAPI 只有 Windows 有，macOS 走 Keychain（未实现）」）。
//!
//! ── 不落凭证 ────────────────────────────────────────────────
//! 本机导入落库的 `secret` 只存一个**引用**（scope），不存 token：token 约 30 天
//! 过期、会被桌面端重新登录替换，复制进账号库只会变成旧凭据，还多一处泄漏面。
//! 转发时由 [`read_credentials`] 现读现解（每次请求一遍，约几毫秒）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic = "abort"`：本文件零 unwrap / expect / panic。

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde_json::Value;

/// 数据目录的环境变量覆盖（测试 / 非常规安装用；与参考实现同名）。
const ENV_DATA: &str = "TELEAGENT_DATA";
/// 配置目录的环境变量覆盖。
const ENV_CONFIG: &str = "TELEAGENT_CONFIG";

/// 桌面端「预置模型」供应商 id（apiKey 的出处）。
const NEW_API_PROVIDER: &str = "NewApi";

/// 客户端版本兜底值（读不到 `instance-marker.json` / `updater.json` 时用）。
const FALLBACK_APP_VERSION: &str = "2.0.0";

/// 本机凭据（已解密、已剥掉 `<tenant>:` 前缀）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credentials {
    /// 账号目录名（`v1_public_<userId>`）。
    pub scope: String,
    /// JWT 本体（不含 `<tenant>:` 前缀）。
    pub token: String,
    /// `X-SuperAgent-Device-Id`。
    pub device_id: String,
    /// `X-SuperAgent-Install-Id`（同时参与签名）。
    pub install_id: String,
    /// JWT 里的 `accountName`（界面显示用；可能为空）。
    pub account_name: Option<String>,
    /// JWT 里的 `accountId`。
    pub account_id: Option<String>,
    /// JWT 里的 `exp`（**秒**）。
    pub expires_at: Option<i64>,
}

/// 用户主目录：Windows 用 `USERPROFILE`，其余用 `HOME`。
pub fn home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    if let Some(value) = std::env::var_os("USERPROFILE") {
        if !value.is_empty() {
            return Some(PathBuf::from(value));
        }
    }
    std::env::var_os("HOME").filter(|value| !value.is_empty()).map(PathBuf::from)
}

/// 桌面端数据目录（`~/.local/share/TeleAgent`）。
pub fn data_dir() -> Option<PathBuf> {
    if let Some(value) = std::env::var_os(ENV_DATA) {
        if !value.is_empty() {
            return Some(PathBuf::from(value));
        }
    }
    home_dir().map(|home| home.join(".local").join("share").join("TeleAgent"))
}

/// 桌面端配置目录（`~/.config/TeleAgent`）。
pub fn config_dir() -> Option<PathBuf> {
    if let Some(value) = std::env::var_os(ENV_CONFIG) {
        if !value.is_empty() {
            return Some(PathBuf::from(value));
        }
    }
    home_dir().map(|home| home.join(".config").join("TeleAgent"))
}

/// 账号目录下带 `token.json` 的作用域列表（新的在前）。
///
/// 排序按 `token.json` 的 mtime 降序 —— 与参考实现同一口径。**不能**按目录名
/// 排序：换过账号之后目录名顺序不可靠。
pub fn list_scopes(data: &Path) -> Vec<String> {
    let users = data.join("users");
    let Ok(entries) = std::fs::read_dir(&users) else {
        return Vec::new();
    };
    let mut candidates: Vec<(SystemTime, String)> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let token = entry.path().join("app-auth").join("token.json");
        let Ok(meta) = std::fs::metadata(&token) else {
            continue;
        };
        let Ok(modified) = meta.modified() else {
            continue;
        };
        candidates.push((modified, name));
    }
    candidates.sort_by(|a, b| b.0.cmp(&a.0));
    candidates.into_iter().map(|(_, name)| name).collect()
}

/// 当前账号的 scope：优先 `current-owner.json`，否则取 `token.json` 最新的那个。
pub fn current_scope(data: &Path) -> Result<String, String> {
    if let Ok(text) = std::fs::read_to_string(data.join("current-owner.json")) {
        if let Ok(value) = serde_json::from_str::<Value>(&text) {
            if let Some(owner) = value.get("ownerDir").and_then(Value::as_str) {
                let owner = owner.trim();
                if !owner.is_empty() {
                    return Ok(owner.to_string());
                }
            }
        }
    }
    list_scopes(data)
        .into_iter()
        .next()
        .ok_or_else(|| "未找到已登录账号（缺少 app-auth/token.json）".to_string())
}

/// 读设备指纹（`app-auth/device-meta.json`）。
///
/// 两个值都参与签名，缺一个上游就拒 —— 所以**任一为空都当作读不到**，
/// 让调用方去报错，而不是凑一对半拉的值去换一个笼统的 401。
pub fn read_device_meta(data: &Path) -> Option<(String, String)> {
    let text = std::fs::read_to_string(data.join("app-auth").join("device-meta.json")).ok()?;
    let value: Value = serde_json::from_str(&text).ok()?;
    let device_id = value.get("deviceId")?.as_str()?.trim().to_string();
    let install_id = value.get("installId")?.as_str()?.trim().to_string();
    if device_id.is_empty() || install_id.is_empty() {
        return None;
    }
    Some((device_id, install_id))
}

/// 剥掉 safeStorage 明文里的 `<tenant>:` 前缀，返回 JWT 本体。
///
/// 明文形状是 `<tenant>:<JWT>`（实测 tenant 是 `Em9xR4` 这种短串）。没有 `:`
/// 时原样返回 —— 宁可把整段当 JWT 交给上游判，也不要把正常内容截掉一截。
pub fn strip_tenant_prefix(plain: &str) -> &str {
    match plain.split_once(':') {
        Some((_, jwt)) => jwt,
        None => plain,
    }
}

/// 取 AES 密钥：`Local State` 里 DPAPI 包着的 os_crypt key。
///
/// DPAPI 只有 Windows 有，所以非 Windows 上这一步**必然失败** —— 让调用方去
/// 报错，而不是退化成「拿整个 token 当 key」。
fn os_crypt_key(data: &Path) -> Result<Vec<u8>, String> {
    #[cfg(windows)]
    {
        crate::crypto::os_crypt_aes_key(&data.join("Local State"))
    }
    #[cfg(not(windows))]
    {
        let _ = data;
        Err("TeleAgent 本机登录态只在 Windows 上可读（DPAPI 是 Windows 独有的）".to_string())
    }
}

/// 解密 `token.json` 里的 `encryptedToken`（Electron safeStorage）。
///
/// Windows 上是 Chromium 的 os_crypt 方案（`v10` + nonce + AES-256-GCM），
/// 与 `crate::crypto::decrypt_os_crypt_blob` 完全一致；密钥来自同一个
/// `Local State`。
pub fn decrypt_safe_storage(data: &Path, encrypted: &str) -> Result<String, String> {
    let key = os_crypt_key(data)?;
    decrypt_safe_storage_with_key(encrypted, &key)
}

/// 用给定的 AES 密钥解密（**纯函数**，便于用例注入密钥 —— DPAPI 只有 Windows 有，
/// 非 Windows 上没法用真实密钥跑通这条链）。
pub fn decrypt_safe_storage_with_key(encrypted: &str, key: &[u8]) -> Result<String, String> {
    let blob = decode_base64(encrypted.trim())?;
    let plain = crate::crypto::decrypt_os_crypt_blob(&blob, key)?;
    String::from_utf8(plain).map_err(|_| "凭据解密结果不是合法 UTF-8".to_string())
}

/// 标准 base64 解码（与 `crate::crypto` 内部那条同一口径：宽容填充）。
fn decode_base64(text: &str) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|_| "凭据不是合法 base64".to_string())
}

/// 读一个账号的凭据（现读现解）。
///
/// `scope` 为空串时用当前账号（[`current_scope`]）。
pub fn read_credentials(data: &Path, scope: &str) -> Result<Credentials, String> {
    let scope = if scope.trim().is_empty() {
        current_scope(data)?
    } else {
        scope.trim().to_string()
    };
    let token_file = data
        .join("users")
        .join(&scope)
        .join("app-auth")
        .join("token.json");
    let text = std::fs::read_to_string(&token_file)
        .map_err(|_| format!("凭据文件不存在：{}", token_file.display()))?;
    let envelope: Value =
        serde_json::from_str(&text).map_err(|_| "凭据文件无法解析（不是有效 JSON）".to_string())?;
    let encrypted = envelope
        .get("encryptedToken")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "凭据文件里没有 encryptedToken".to_string())?;
    let plain = decrypt_safe_storage(data, encrypted)?;
    let token = strip_tenant_prefix(&plain).to_string();
    if token.split('.').count() != 3 {
        return Err("解密出来的不是 JWT（应为三段点分），请确认粘贴/读取的是 token.json".to_string());
    }
    let (device_id, install_id) = read_device_meta(data)
        .ok_or_else(|| "未找到设备指纹（app-auth/device-meta.json）".to_string())?;
    let claims = crate::crypto::decode_jwt_claims(&token);
    let (account_name, account_id, expires_at) = match claims {
        Some(claims) => (
            claims
                .get("accountName")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string),
            claims
                .get("accountId")
                .map(|value| match value {
                    Value::String(text) => text.clone(),
                    other => other.to_string(),
                })
                .filter(|value| !value.is_empty()),
            claims.get("exp").and_then(Value::as_i64),
        ),
        None => (None, None, None),
    };
    Ok(Credentials {
        scope,
        token,
        device_id,
        install_id,
        account_name,
        account_id,
        expires_at,
    })
}

/// 客户端版本号（`X-App-Version` 头用）。
///
/// 优先读运行中的 `instance-marker.json`（最准），其次 `updater.json` 的
/// `lastVersion`，都读不到就用兜底常量。签名头里的版本号与上游的灰度/版本门
/// 有关，**读不到时不要编一个** —— 用兜底常量，让上游自己判。
pub fn app_version(data: &Path) -> String {
    if let Ok(text) = std::fs::read_to_string(data.join("instance-marker.json")) {
        if let Ok(value) = serde_json::from_str::<Value>(&text) {
            if let Some(version) = value.get("version").and_then(Value::as_str) {
                let version = version.trim();
                if !version.is_empty() {
                    return version.to_string();
                }
            }
        }
    }
    if let Ok(text) = std::fs::read_to_string(data.join("updater.json")) {
        if let Ok(value) = serde_json::from_str::<Value>(&text) {
            if let Some(version) = value.get("lastVersion").and_then(Value::as_str) {
                let version = version.trim();
                if !version.is_empty() {
                    return version.to_string();
                }
            }
        }
    }
    FALLBACK_APP_VERSION.to_string()
}

/// 从账号配置 `~/.config/TeleAgent/users/<scope>/TeleAgent.jsonc` 读网关 apiKey。
///
/// 用户改过供应商配置时，客户端会把 `provider.NewApi.options.apiKey` 写进这个
/// 文件。它是 `.jsonc`（可能带注释与尾逗号），所以先做一次最小清洗再解析。
pub fn read_api_key_from_config(config: &Path, scope: &str) -> Option<String> {
    let file = config
        .join("users")
        .join(scope)
        .join("TeleAgent.jsonc");
    let text = std::fs::read_to_string(file).ok()?;
    let value: Value = serde_json::from_str(&strip_jsonc(&text)).ok()?;
    let key = value
        .get("provider")?
        .get(NEW_API_PROVIDER)?
        .get("options")?
        .get("apiKey")?
        .as_str()?
        .trim()
        .to_string();
    if key.is_empty() {
        None
    } else {
        Some(key)
    }
}

/// 去掉 `.jsonc` 的注释与尾逗号（最小实现，只服务上面那一个读取）。
///
/// 只处理 `//` 行注释与**尾逗号**（逗号后面跳过空白是 `}` / `]`）—— 不做完整
/// JSONC 解析：这个文件是客户端自己写的，形状稳定，过度实现只会多一处出错的地方。
fn strip_jsonc(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut in_string = false;
    let mut escaped = false;
    let mut index = 0;
    while index < chars.len() {
        let ch = chars[index];
        if in_string {
            out.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if ch == '"' {
            in_string = true;
            out.push(ch);
            index += 1;
            continue;
        }
        if ch == '/' && chars.get(index + 1) == Some(&'/') {
            while index < chars.len() && chars[index] != '\n' {
                index += 1;
            }
            continue;
        }
        if ch == ',' {
            let mut look = index + 1;
            while look < chars.len() && chars[look].is_whitespace() {
                look += 1;
            }
            if look < chars.len() && (chars[look] == '}' || chars[look] == ']') {
                index += 1;
                continue;
            }
        }
        out.push(ch);
        index += 1;
    }
    out
}

/// 已安装的 `app.asar` 路径候选（按优先级）。
fn asar_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let mut bases: Vec<PathBuf> = Vec::new();
    for name in ["ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"] {
        if let Some(value) = std::env::var_os(name) {
            if !value.is_empty() {
                bases.push(PathBuf::from(value));
            }
        }
    }
    if let Some(value) = std::env::var_os("LOCALAPPDATA") {
        if !value.is_empty() {
            bases.push(PathBuf::from(value).join("Programs"));
        }
    }
    for base in bases {
        paths.push(base.join("TeleAgent").join("resources").join("app.asar"));
    }
    paths
}

/// 从桌面端安装包 `app.asar` 里读网关 apiKey。
///
/// 这个 key 是**桌面端内置常量**（「预置模型」供应商的 `options.apiKey`），
/// 不写进仓库 —— 运行时按 `配置 → 环境变量 → 账号配置 → app.asar` 四级解析。
///
/// asar 是「16 字节 pickle 头 + JSON 头 + 顺序文件体」：这里只读本地字节，
/// 不解包、不写盘、不联网。文件可能很大（本机 860 MB），所以**只 seek 目标
/// 那一段**（`main-runtime-*.js`，约 4 MB），不整读。
pub fn read_api_key_from_asar() -> Option<String> {
    for asar in asar_paths() {
        if let Some(key) = read_api_key_from_asar_file(&asar) {
            return Some(key);
        }
    }
    None
}

/// 单个 asar 的解析（抽出来是为了能拿自造的小 asar 做用例）。
fn read_api_key_from_asar_file(asar: &Path) -> Option<String> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    let mut file = std::fs::File::open(asar).ok()?;
    let mut head = [0u8; 16];
    file.read_exact(&mut head).ok()?;
    let header_size = u32::from_le_bytes([head[4], head[5], head[6], head[7]]) as u64;
    let json_len = u32::from_le_bytes([head[12], head[13], head[14], head[15]]) as u64;
    if header_size == 0 || json_len == 0 || json_len > 64 * 1024 * 1024 {
        return None;
    }
    let mut header_raw = vec![0u8; json_len as usize];
    file.read_exact(&mut header_raw).ok()?;
    let header: Value = serde_json::from_slice(&header_raw).ok()?;

    // 找到 main runtime 那条记录（不同版本文件名带不同的 hash 后缀）
    let runtime = find_asar_file(&header, "dist-electron", "main-runtime-")?;
    let size = runtime.get("size").and_then(Value::as_u64)?;
    let offset = runtime.get("offset").and_then(Value::as_u64)?;
    if size == 0 || size > 64 * 1024 * 1024 {
        return None;
    }
    // 文件体起点：实测 `8 + header_size`（pickle 头 8 字节 + header 段）。
    // 另有实现按 `16 + json_len` 算，会差 2 字节；两个都试一次，取能读到
    // `new-api` 锚点的那个。
    for base in [8 + header_size, 16 + json_len] {
        if file.seek(SeekFrom::Start(base + offset)).is_err() {
            continue;
        }
        let mut buf = vec![0u8; size as usize];
        if file.read_exact(&mut buf).is_err() {
            continue;
        }
        let Ok(text) = String::from_utf8(buf) else {
            continue;
        };
        if let Some(key) = extract_new_api_key(&text) {
            return Some(key);
        }
    }
    None
}

/// 在 asar 的 JSON 头里找 `dist-electron/<prefix>*.js` 那条文件记录。
/// 在 asar 的 JSON 头里找 `main-runtime-*.js` 那条文件记录。
///
/// 优先只看 `dist-electron/` 那个目录（不同版本的 main runtime 都在里面）；
/// 找不到再整棵树兜底 —— 目录名变过也能用，代价是可能命中别的同名前缀文件。
fn find_asar_file<'a>(node: &'a Value, dir: &str, prefix: &str) -> Option<&'a Value> {
    let files = node.get("files")?.as_object()?;
    if !dir.is_empty() {
        if let Some(inside) = files
            .get(dir)
            .and_then(|value| value.get("files"))
            .and_then(|value| value.as_object())
        {
            for (name, meta) in inside {
                if name.ends_with(".js") && name.starts_with(prefix) {
                    return Some(meta);
                }
            }
        }
    }
    for (_, meta) in files {
        // 递归进目录条目（目录条目的形状是 `{"files": {…}}`）；文件条目
        // （没有 `files`）在上一轮就被前缀判据收掉了，不会无限递归
        if meta.get("files").is_some() {
            if let Some(found) = find_asar_file(meta, "", prefix) {
                return Some(found);
            }
        }
    }
    None
}

/// 从 main runtime 的文本里抽「预置模型」供应商的 apiKey。
///
/// **只认 `id: "new-api"` 之后那一段**：文件里还有别的 apiKey 常量
/// （内网代理用的），抓错会把一个无关的 key 当网关凭据发出去。
fn extract_new_api_key(text: &str) -> Option<String> {
    let anchor = text.find("id: \"new-api\"")?;
    // 只往后看一小段：`new-api` 之后紧跟着它自己的 options
    let end = (anchor + 1200).min(text.len());
    let scope = text.get(anchor..end)?;
    let start = scope.find("apiKey:")? + "apiKey:".len();
    let rest = scope.get(start..)?;
    let quote = rest.find('"')?;
    let rest = rest.get(quote + 1..)?;
    let end = rest.find('"')?;
    let key = rest.get(..end)?;
    if key.len() >= 8 && key.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-') {
        Some(key.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// 建一个临时目录，返回路径（用例结束不清理也行，系统会清 temp）。
    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("teleagent-desktop-{label}-{}", crate::ids::uuid_v4()));
        std::fs::create_dir_all(&dir).expect("创建临时目录");
        dir
    }

    fn write(path: &Path, text: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("创建父目录");
        }
        std::fs::write(path, text).expect("写临时文件");
    }

    #[test]
    fn current_scope_prefers_current_owner() {
        let dir = temp_dir("owner");
        write(&dir.join("current-owner.json"), r#"{"ownerDir":"v1_public_one"}"#);
        write(&dir.join("users/v1_public_one/app-auth/token.json"), "{}");
        write(&dir.join("users/v1_public_two/app-auth/token.json"), "{}");
        assert_eq!(current_scope(&dir).expect("应当读到当前账号"), "v1_public_one");
    }

    #[test]
    fn current_scope_falls_back_to_newest_token() {
        let dir = temp_dir("newest");
        let old = dir.join("users/v1_public_old/app-auth/token.json");
        let new = dir.join("users/v1_public_new/app-auth/token.json");
        write(&old, "{}");
        // 让 new 的 mtime 明确更晚：标准库没有设 mtime 的接口，只能等。
        std::thread::sleep(std::time::Duration::from_millis(30));
        write(&new, "{}");
        assert_eq!(current_scope(&dir).expect("应当回落到最新"), "v1_public_new");
        assert_eq!(list_scopes(&dir).first().map(String::as_str), Some("v1_public_new"));
    }

    #[test]
    fn device_meta_requires_both_fields() {
        let dir = temp_dir("meta");
        write(&dir.join("app-auth/device-meta.json"), r#"{"deviceId":"d1","installId":"i1"}"#);
        assert_eq!(read_device_meta(&dir), Some(("d1".to_string(), "i1".to_string())));

        write(&dir.join("app-auth/device-meta.json"), r#"{"deviceId":"d1"}"#);
        assert_eq!(read_device_meta(&dir), None, "缺 installId 必须当作读不到");
    }

    #[test]
    fn tenant_prefix_is_stripped() {
        assert_eq!(strip_tenant_prefix("Em9xR4:aaa.bbb.ccc"), "aaa.bbb.ccc");
        assert_eq!(strip_tenant_prefix("aaa.bbb.ccc"), "aaa.bbb.ccc");
    }

    #[test]
    fn non_v10_blob_is_rejected_before_decrypt() {
        let dir = temp_dir("v10");
        // 直接调底层：Windows 之外的平台分支会先报「只在 Windows 上可读」，
        // 所以这里只断言「不会 panic，且给的是错误」。
        let outcome = decrypt_safe_storage(&dir, "bm90LWEtYmxvYg==");
        assert!(outcome.is_err());
    }

    /// 用合成密钥跑通「base64 → `v10` → AES-256-GCM → UTF-8」这条链。
    ///
    /// DPAPI 只有 Windows 有，非 Windows 上跑不了真实密钥；但解密链本身是平台无关的
    /// （nonce / tag 的 Postfix 拼法与 `crate::crypto` 的 `decrypt_os_crypt_blob`
    /// 完全一致），所以用一个自造的密钥 + 明文把它钉住。
    #[test]
    fn a_safe_storage_blob_decrypts_with_a_known_key() {
        use aes_gcm::aead::{Aead as _, KeyInit as _};
        use aes_gcm::{Aes256Gcm, Nonce};
        use base64::Engine as _;

        let key = [7u8; 32];
        let cipher = Aes256Gcm::new_from_slice(&key).expect("AES-256 密钥长度固定");
        let nonce_bytes = [3u8; 12];
        let plaintext = b"Em9xR4:aaa.bbb.ccc";
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_ref())
            .expect("加密应当成功");

        // 与 Chromium 的拼法一致：版本前缀 + nonce + 密文（tag 附在尾部）
        let mut blob = b"v10".to_vec();
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ciphertext);
        let encoded = base64::engine::general_purpose::STANDARD.encode(&blob);

        let decoded = decrypt_safe_storage_with_key(&encoded, &key).expect("应当解出明文");
        assert_eq!(decoded, "Em9xR4:aaa.bbb.ccc");
        assert_eq!(strip_tenant_prefix(&decoded), "aaa.bbb.ccc");

        // 密钥不对必须失败，不能退化成明文
        assert!(decrypt_safe_storage_with_key(&encoded, &[9u8; 32]).is_err());
    }

    #[test]
    fn app_version_prefers_instance_marker() {
        let dir = temp_dir("version");
        write(&dir.join("updater.json"), r#"{"lastVersion":"1.2.3"}"#);
        assert_eq!(app_version(&dir), "1.2.3");

        write(&dir.join("instance-marker.json"), r#"{"version":"9.9.9"}"#);
        assert_eq!(app_version(&dir), "9.9.9");

        let empty = temp_dir("version-empty");
        assert_eq!(app_version(&empty), FALLBACK_APP_VERSION);
    }

    #[test]
    fn config_api_key_is_read_through_jsonc() {
        let dir = temp_dir("cfg");
        write(
            &dir.join("users/v1_public_1/TeleAgent.jsonc"),
            "{\n // 注释\n \"provider\": { \"NewApi\": { \"options\": { \"apiKey\": \"sk-test-123\" } } },\n}",
        );
        assert_eq!(
            read_api_key_from_config(&dir, "v1_public_1"),
            Some("sk-test-123".to_string())
        );
        assert_eq!(read_api_key_from_config(&dir, "v1_public_missing"), None);
    }

    #[test]
    fn asar_key_is_read_from_the_new_api_provider_only() {
        let dir = temp_dir("asar");
        let asar = dir.join("app.asar");
        // 自造一个最小 asar：16 字节 pickle 头 + JSON 头 + 2 字节填充 + 文件体
        // （真实 asar 里 JSON 头与文件体之间有 2 字节填充，文件体起点按
        // `8 + header_size` 算 —— 见 `read_api_key_from_asar_file`）
        let runtime = "const a = { id: \"other\", apiKey: \"sk-wrong-key\" };\n\
                       const b = { id: \"new-api\", apiKey: \"sk-right-key\" };\n";
        let pad = "module.exports = 1;\n";
        let files = json!({
            "files": {
                "dist-electron": {
                    "files": {
                        "main-runtime-aaaa.js": { "size": runtime.len(), "offset": 0 },
                        "pad.js": { "size": pad.len(), "offset": runtime.len() },
                    }
                }
            }
        });
        let header = files.to_string().into_bytes();
        let json_len = header.len() as u32;
        let header_size = json_len + 10;
        let mut blob = Vec::new();
        blob.extend_from_slice(&4u32.to_le_bytes());
        blob.extend_from_slice(&header_size.to_le_bytes());
        blob.extend_from_slice(&(json_len + 6).to_le_bytes());
        blob.extend_from_slice(&json_len.to_le_bytes());
        blob.extend_from_slice(&header);
        blob.extend_from_slice(&[0u8; 2]);
        blob.extend_from_slice(runtime.as_bytes());
        blob.extend_from_slice(pad.as_bytes());
        std::fs::write(&asar, blob).expect("写 asar");

        assert_eq!(read_api_key_from_asar_file(&asar), Some("sk-right-key".to_string()));
    }

    #[test]
    fn jsonc_comments_and_trailing_commas_are_removed() {
        let stripped = strip_jsonc("{\n // c\n \"a\": { \"b\": 1 },\n \"c\": 2 ,\n}");
        assert!(stripped.contains("\"a\""), "实际：{stripped}");
        assert!(!stripped.contains("//"), "注释应当被去掉，实际：{stripped}");
        // 尾逗号（后面有空白）也要去掉
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&stripped).is_ok(),
            true,
            "清洗后应当是合法 JSON：{stripped}"
        );
    }
}

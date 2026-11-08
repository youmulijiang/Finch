//! Decoder pipeline engine: operation registry, step model and execution.
//!
//! Every operation consumes and produces raw bytes (`Vec<u8>`), so binary
//! intermediates (decrypted ciphertext, raw digests, ...) survive between
//! steps. Rendering to text/hex/base64 is purely a display concern.

use serde::{Deserialize, Serialize};

use base64::Engine as _;
use md5::Digest as _;

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

// ---------------------------------------------------------------- model

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum BlockMode {
    #[default]
    Ecb,
    Cbc,
}

impl BlockMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ecb => "ECB",
            Self::Cbc => "CBC",
        }
    }
}

/// How key / IV strings typed into the UI are interpreted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum KeyEncoding {
    #[default]
    Hex,
    Utf8,
}

impl KeyEncoding {
    pub fn label(self) -> &'static str {
        match self {
            Self::Hex => "Hex",
            Self::Utf8 => "UTF-8",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Category {
    Encoding,
    Hash,
    Crypto,
    /// Chinese national cryptography standards (SM2/SM3/SM4 family).
    Guomi,
    /// JSON Web Token operations.
    Jwt,
}

impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Self::Encoding => "Encoding",
            Self::Hash => "Hash",
            Self::Crypto => "Crypto",
            Self::Guomi => "国密 (Chinese national crypto)",
            Self::Jwt => "JWT",
        }
    }
}

/// One configurable operation in the recipe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OpKind {
    Base64Encode,
    Base64Decode,
    HexEncode,
    HexDecode,
    UrlEncode,
    UrlDecode,
    HtmlEncode,
    HtmlDecode,
    Md5,
    Sha1,
    Sha256,
    /// SM3 (GB/T 32905) hash, 256-bit digest.
    Sm3,
    /// AES-128/192/256 selected by key length.
    AesCrypt {
        enc: bool,
        mode: BlockMode,
    },
    /// SM4 (GB/T 32907), 128-bit key.
    Sm4Crypt {
        enc: bool,
        mode: BlockMode,
    },
    /// DES (8-byte key) or 3DES (24-byte key).
    DesCrypt {
        enc: bool,
        triple: bool,
        mode: BlockMode,
    },
    /// RC4 stream cipher; symmetric, same call both directions.
    Rc4Crypt,
    /// AES-GCM (128/256 by key length). Ciphertext carries the 16-byte tag.
    AesGcmCrypt {
        enc: bool,
    },
    /// Decode a JWT: pretty header + payload + signature info.
    JwtDecode,
    /// Sign the input (claims JSON) as a JWT with HS256 and the key secret.
    JwtSign,
    /// Verify an HS256 JWT against the key secret; outputs the claims.
    JwtVerify,
}

impl OpKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Base64Encode => "Base64 Encode",
            Self::Base64Decode => "Base64 Decode",
            Self::HexEncode => "Hex Encode",
            Self::HexDecode => "Hex Decode",
            Self::UrlEncode => "URL Encode",
            Self::UrlDecode => "URL Decode",
            Self::HtmlEncode => "HTML Entities Encode",
            Self::HtmlDecode => "HTML Entities Decode",
            Self::Md5 => "MD5",
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
            Self::Sm3 => "SM3",
            Self::JwtDecode => "JWT Decode",
            Self::JwtSign => "JWT Sign (HS256)",
            Self::JwtVerify => "JWT Verify (HS256)",
            Self::AesCrypt { enc, mode } => match (enc, mode) {
                (true, BlockMode::Ecb) => "AES ECB Encrypt",
                (true, BlockMode::Cbc) => "AES CBC Encrypt",
                (false, BlockMode::Ecb) => "AES ECB Decrypt",
                (false, BlockMode::Cbc) => "AES CBC Decrypt",
            },
            Self::Sm4Crypt { enc, mode } => match (enc, mode) {
                (true, BlockMode::Ecb) => "SM4 ECB Encrypt",
                (true, BlockMode::Cbc) => "SM4 CBC Encrypt",
                (false, BlockMode::Ecb) => "SM4 ECB Decrypt",
                (false, BlockMode::Cbc) => "SM4 CBC Decrypt",
            },
            Self::DesCrypt { enc, triple, mode } => match (enc, triple, mode) {
                (true, false, BlockMode::Ecb) => "DES ECB Encrypt",
                (false, false, BlockMode::Ecb) => "DES ECB Decrypt",
                (true, false, BlockMode::Cbc) => "DES CBC Encrypt",
                (false, false, BlockMode::Cbc) => "DES CBC Decrypt",
                (true, true, BlockMode::Ecb) => "3DES ECB Encrypt",
                (false, true, BlockMode::Ecb) => "3DES ECB Decrypt",
                (true, true, BlockMode::Cbc) => "3DES CBC Encrypt",
                (false, true, BlockMode::Cbc) => "3DES CBC Decrypt",
            },
            Self::Rc4Crypt => "RC4",
            Self::AesGcmCrypt { enc } => {
                if enc {
                    "AES-GCM Encrypt"
                } else {
                    "AES-GCM Decrypt"
                }
            }
        }
    }

    pub fn category(self) -> Category {
        match self {
            Self::Base64Encode
            | Self::Base64Decode
            | Self::HexEncode
            | Self::HexDecode
            | Self::UrlEncode
            | Self::UrlDecode
            | Self::HtmlEncode
            | Self::HtmlDecode => Category::Encoding,
            Self::Md5 | Self::Sha1 | Self::Sha256 => Category::Hash,
            Self::Sm3 | Self::Sm4Crypt { .. } => Category::Guomi,
            Self::JwtDecode | Self::JwtSign | Self::JwtVerify => Category::Jwt,
            Self::AesCrypt { .. }
            | Self::DesCrypt { .. }
            | Self::Rc4Crypt
            | Self::AesGcmCrypt { .. } => Category::Crypto,
        }
    }

    pub fn needs_key(self) -> bool {
        matches!(
            self,
            Self::AesCrypt { .. }
                | Self::Sm4Crypt { .. }
                | Self::DesCrypt { .. }
                | Self::Rc4Crypt
                | Self::AesGcmCrypt { .. }
                | Self::JwtSign
                | Self::JwtVerify
        )
    }

    /// CBC needs a 16-byte IV (8 for DES), GCM a 12-byte nonce.
    pub fn needs_iv(self) -> bool {
        matches!(
            self,
            Self::AesCrypt {
                mode: BlockMode::Cbc,
                ..
            } | Self::Sm4Crypt {
                mode: BlockMode::Cbc,
                ..
            } | Self::DesCrypt {
                mode: BlockMode::Cbc,
                ..
            } | Self::AesGcmCrypt { .. }
        )
    }

    pub fn is_gcm(self) -> bool {
        matches!(self, Self::AesGcmCrypt { .. })
    }
}

/// Library entry: one row in the operations column. Crypto families appear
/// once; direction / mode are then picked with dropdowns in the recipe step.
pub struct OpEntry {
    pub label: &'static str,
    /// Kind appended to the recipe when the entry is added.
    pub default: OpKind,
    pub category: Category,
}

const fn entry(label: &'static str, default: OpKind, category: Category) -> OpEntry {
    OpEntry {
        label,
        default,
        category,
    }
}

/// Registry shown in the operations library. Order = display order.
pub const OP_ENTRIES: &[OpEntry] = &[
    entry("Base64 Encode", OpKind::Base64Encode, Category::Encoding),
    entry("Base64 Decode", OpKind::Base64Decode, Category::Encoding),
    entry("Hex Encode", OpKind::HexEncode, Category::Encoding),
    entry("Hex Decode", OpKind::HexDecode, Category::Encoding),
    entry("URL Encode", OpKind::UrlEncode, Category::Encoding),
    entry("URL Decode", OpKind::UrlDecode, Category::Encoding),
    entry(
        "HTML Entities Encode",
        OpKind::HtmlEncode,
        Category::Encoding,
    ),
    entry(
        "HTML Entities Decode",
        OpKind::HtmlDecode,
        Category::Encoding,
    ),
    entry("MD5", OpKind::Md5, Category::Hash),
    entry("SHA-1", OpKind::Sha1, Category::Hash),
    entry("SHA-256", OpKind::Sha256, Category::Hash),
    entry(
        "AES",
        OpKind::AesCrypt {
            enc: true,
            mode: BlockMode::Cbc,
        },
        Category::Crypto,
    ),
    entry(
        "AES-GCM",
        OpKind::AesGcmCrypt { enc: true },
        Category::Crypto,
    ),
    entry(
        "DES",
        OpKind::DesCrypt {
            enc: true,
            triple: false,
            mode: BlockMode::Cbc,
        },
        Category::Crypto,
    ),
    entry(
        "3DES",
        OpKind::DesCrypt {
            enc: true,
            triple: true,
            mode: BlockMode::Cbc,
        },
        Category::Crypto,
    ),
    entry(
        "SM4",
        OpKind::Sm4Crypt {
            enc: true,
            mode: BlockMode::Cbc,
        },
        Category::Guomi,
    ),
    entry("SM3", OpKind::Sm3, Category::Guomi),
    entry("RC4", OpKind::Rc4Crypt, Category::Crypto),
    entry("JWT Decode", OpKind::JwtDecode, Category::Jwt),
    entry("JWT Sign (HS256)", OpKind::JwtSign, Category::Jwt),
    entry("JWT Verify (HS256)", OpKind::JwtVerify, Category::Jwt),
];

/// Per-step parameters (key material, IV/nonce, GCM associated data).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StepParams {
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub iv: String,
    #[serde(default)]
    pub aad: String,
    #[serde(default)]
    pub key_enc: KeyEncoding,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Step {
    pub kind: OpKind,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub params: StepParams,
}

fn default_true() -> bool {
    true
}

impl Step {
    pub fn new(kind: OpKind) -> Self {
        Self {
            kind,
            enabled: true,
            params: StepParams::default(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct StepResult {
    pub data: Vec<u8>,
    pub error: Option<String>,
}

// ---------------------------------------------------------------- execution

/// Run the recipe step by step. Disabled steps pass data through; once a
/// step fails the error is recorded and the remaining enabled steps are
/// marked skipped.
pub fn run_pipeline(input: &[u8], steps: &[Step]) -> Vec<StepResult> {
    let mut results = Vec::with_capacity(steps.len());
    let mut cur = input.to_vec();
    let mut failed = false;
    for step in steps {
        if !step.enabled {
            results.push(StepResult {
                data: cur.clone(),
                error: None,
            });
            continue;
        }
        if failed {
            results.push(StepResult {
                data: cur.clone(),
                error: Some("skipped: an earlier step failed".into()),
            });
            continue;
        }
        match exec(step, &cur) {
            Ok(out) => {
                cur = out.clone();
                results.push(StepResult {
                    data: out,
                    error: None,
                });
            }
            Err(e) => {
                failed = true;
                results.push(StepResult {
                    data: cur.clone(),
                    error: Some(e),
                });
            }
        }
    }
    results
}

fn e2s<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

const ERR_PAD: &str = "bad padding: wrong key or corrupted ciphertext?";
const ERR_UNPADDED: &str = "ciphertext length is not a multiple of the block size";
const ERR_TAG: &str = "authentication failed: wrong key, nonce or corrupted data";

/// Parse a key/IV string according to its declared encoding.
fn key_bytes(s: &str, enc: KeyEncoding) -> Result<Vec<u8>, String> {
    match enc {
        KeyEncoding::Hex => {
            let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
            hex::decode(&clean).map_err(|e| format!("bad hex: {e}"))
        }
        KeyEncoding::Utf8 => Ok(s.as_bytes().to_vec()),
    }
}

fn expect_len(what: &str, bytes: &[u8], want: usize) -> Result<(), String> {
    if bytes.len() != want {
        return Err(format!(
            "{what} must be {want} bytes ({want} UTF-8 chars or {want}×2 hex chars), got {}",
            bytes.len()
        ));
    }
    Ok(())
}

fn expect_key_len(what: &str, bytes: &[u8], want: usize) -> Result<(), String> {
    expect_len(what, bytes, want).map_err(|e| format!("key: {e}"))
}

/// Generate a encrypt/decrypt pair for one block cipher via ecb/cbc crates.
macro_rules! block_alg {
    ($fname:ident, $ct:ty) => {
        fn $fname(
            enc: bool,
            use_cbc: bool,
            data: &[u8],
            key: &[u8],
            iv: &[u8],
        ) -> Result<Vec<u8>, String> {
            use aes::cipher::{
                BlockModeDecrypt, BlockModeEncrypt, KeyInit, KeyIvInit, block_padding::Pkcs7,
            };
            if use_cbc {
                if enc {
                    Ok(cbc::Encryptor::<$ct>::new_from_slices(key, iv)
                        .map_err(e2s)?
                        .encrypt_padded_vec::<Pkcs7>(data))
                } else {
                    cbc::Decryptor::<$ct>::new_from_slices(key, iv)
                        .map_err(e2s)?
                        .decrypt_padded_vec::<Pkcs7>(data)
                        .map_err(|_| ERR_PAD.to_string())
                }
            } else if enc {
                Ok(ecb::Encryptor::<$ct>::new_from_slice(key)
                    .map_err(e2s)?
                    .encrypt_padded_vec::<Pkcs7>(data))
            } else {
                ecb::Decryptor::<$ct>::new_from_slice(key)
                    .map_err(e2s)?
                    .decrypt_padded_vec::<Pkcs7>(data)
                    .map_err(|_| ERR_PAD.to_string())
            }
        }
    };
}

block_alg!(aes128_block, aes::Aes128);
block_alg!(aes192_block, aes::Aes192);
block_alg!(aes256_block, aes::Aes256);
block_alg!(sm4_block, sm4::Sm4);
block_alg!(des_block, des::Des);
block_alg!(des3_block, des::TdesEde3);

type BlockFn = fn(bool, bool, &[u8], &[u8], &[u8]) -> Result<Vec<u8>, String>;

/// Block-cipher call description, so `run_block` stays readable.
struct BlockArgs<'a> {
    enc: bool,
    mode: BlockMode,
    data: &'a [u8],
    key: &'a [u8],
    iv: &'a str,
    iv_enc: KeyEncoding,
    iv_len: usize,
    /// Cipher block size in bytes (AES/SM4 = 16, DES/3DES = 8).
    block_size: usize,
}

/// Shared driver: picks the mode, validates IV length, calls the alg fn.
fn run_block(args: BlockArgs<'_>, alg: BlockFn) -> Result<Vec<u8>, String> {
    let BlockArgs {
        enc,
        mode,
        data,
        key,
        iv,
        iv_enc,
        iv_len,
        block_size,
    } = args;
    if !data.len().is_multiple_of(block_size) && !enc && mode == BlockMode::Cbc {
        return Err(ERR_UNPADDED.into());
    }
    if mode == BlockMode::Cbc {
        let iv = key_bytes(iv, iv_enc).map_err(|e| format!("IV: {e}"))?;
        expect_len("IV", &iv, iv_len)?;
        alg(enc, true, data, key, &iv)
    } else {
        alg(enc, false, data, key, &[])
    }
}

fn rc4(data: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    use rc4::{KeyInit, StreamCipher};
    if key.is_empty() || key.len() > 256 {
        return Err(format!("RC4 key must be 1..=256 bytes, got {}", key.len()));
    }
    let mut out = data.to_vec();
    rc4::Rc4::new_from_slice(key)
        .map_err(e2s)?
        .apply_keystream(&mut out);
    Ok(out)
}

fn aes_gcm(
    enc: bool,
    data: &[u8],
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    use aes::cipher::consts::U12;
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};

    expect_len("nonce (IV)", nonce, 12)?;
    let payload = Payload { msg: data, aad };
    match key.len() {
        16 => {
            let cipher = Aes128Gcm::new_from_slice(key).map_err(e2s)?;
            let nonce: Nonce<U12> = nonce.try_into().map_err(|_| "bad nonce length")?;
            if enc {
                cipher.encrypt(&nonce, payload).map_err(|_| ERR_TAG.into())
            } else {
                cipher.decrypt(&nonce, payload).map_err(|_| ERR_TAG.into())
            }
        }
        32 => {
            let cipher = Aes256Gcm::new_from_slice(key).map_err(e2s)?;
            let nonce: Nonce<U12> = nonce.try_into().map_err(|_| "bad nonce length")?;
            if enc {
                cipher.encrypt(&nonce, payload).map_err(|_| ERR_TAG.into())
            } else {
                cipher.decrypt(&nonce, payload).map_err(|_| ERR_TAG.into())
            }
        }
        n => Err(format!("AES-GCM key must be 16 or 32 bytes, got {n}")),
    }
}

fn exec(step: &Step, input: &[u8]) -> Result<Vec<u8>, String> {
    let p = &step.params;
    match step.kind {
        OpKind::Base64Encode => Ok(BASE64.encode(input).into_bytes()),
        OpKind::Base64Decode => {
            let clean: String = std::str::from_utf8(input)
                .map_err(|_| "input is not valid UTF-8 text".to_string())?
                .split_whitespace()
                .collect();
            // Tolerate missing padding and the URL-safe alphabet (JWT-style
            // inputs, hand-pasted tokens, ...): try standard, then no-pad,
            // then URL-safe variants.
            BASE64
                .decode(&clean)
                .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(&clean))
                .or_else(|_| {
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&clean)
                })
                .or_else(|_| {
                    base64::engine::general_purpose::URL_SAFE.decode(&clean)
                })
                .map_err(|e| format!("bad base64: {e}"))
        }
        OpKind::HexEncode => Ok(hex::encode(input).into_bytes()),
        OpKind::HexDecode => {
            let s = std::str::from_utf8(input)
                .map_err(|_| "input is not valid UTF-8 text".to_string())?;
            let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
            if !clean.len().is_multiple_of(2) {
                return Err("odd number of hex digits".into());
            }
            hex::decode(&clean).map_err(|e| format!("bad hex: {e}"))
        }
        OpKind::UrlEncode => Ok(percent_encode_strict(input)),
        OpKind::UrlDecode => Ok(url_decode(input)),
        OpKind::HtmlEncode => Ok(html_encode(input).into_bytes()),
        OpKind::HtmlDecode => html_decode(input),
        OpKind::Md5 => Ok(md5::Md5::digest(input).to_vec()),
        OpKind::Sha1 => Ok(sha1::Sha1::digest(input).to_vec()),
        OpKind::Sha256 => Ok(sha2::Sha256::digest(input).to_vec()),
        OpKind::Sm3 => {
            use sm3::Digest as _;
            Ok(sm3::Sm3::digest(input).to_vec())
        }
        OpKind::JwtDecode => jwt_decode(input),
        OpKind::JwtSign => {
            let secret = jwt_secret(&p.key, p.key_enc)?;
            jwt_sign(input, &secret)
        }
        OpKind::JwtVerify => {
            let secret = jwt_secret(&p.key, p.key_enc)?;
            jwt_verify(input, &secret)
        }
        OpKind::AesCrypt { enc, mode } => {
            let key = key_bytes(&p.key, p.key_enc).map_err(|e| format!("key: {e}"))?;
            let alg: BlockFn = match key.len() {
                16 => aes128_block,
                24 => aes192_block,
                32 => aes256_block,
                n => return Err(format!("AES key must be 16/24/32 bytes, got {n}")),
            };
            run_block(
                BlockArgs {
                    enc,
                    mode,
                    data: input,
                    key: &key,
                    iv: &p.iv,
                    iv_enc: p.key_enc,
                    iv_len: 16,
                    block_size: 16,
                },
                alg,
            )
        }
        OpKind::Sm4Crypt { enc, mode } => {
            let key = key_bytes(&p.key, p.key_enc).map_err(|e| format!("key: {e}"))?;
            expect_key_len("SM4", &key, 16)?;
            run_block(
                BlockArgs {
                    enc,
                    mode,
                    data: input,
                    key: &key,
                    iv: &p.iv,
                    iv_enc: p.key_enc,
                    iv_len: 16,
                    block_size: 16,
                },
                sm4_block,
            )
        }
        OpKind::DesCrypt { enc, triple, mode } => {
            let key = key_bytes(&p.key, p.key_enc).map_err(|e| format!("key: {e}"))?;
            let (alg, klen) = if triple {
                (des3_block as BlockFn, 24)
            } else {
                (des_block as BlockFn, 8)
            };
            expect_key_len(if triple { "3DES" } else { "DES" }, &key, klen)?;
            run_block(
                BlockArgs {
                    enc,
                    mode,
                    data: input,
                    key: &key,
                    iv: &p.iv,
                    iv_enc: p.key_enc,
                    iv_len: 8,
                    block_size: 8,
                },
                alg,
            )
        }
        OpKind::Rc4Crypt => {
            let key = key_bytes(&p.key, p.key_enc).map_err(|e| format!("key: {e}"))?;
            rc4(input, &key)
        }
        OpKind::AesGcmCrypt { enc } => {
            let key = key_bytes(&p.key, p.key_enc).map_err(|e| format!("key: {e}"))?;
            let nonce = key_bytes(&p.iv, p.key_enc).map_err(|e| format!("nonce: {e}"))?;
            aes_gcm(enc, input, &key, &nonce, p.aad.as_bytes())
        }
    }
}

// ---------------------------------------------------------------- jwt ops

const JWT_B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Decode a JWT's base64url segment, tolerating stray padding '='.
fn jwt_b64_decode(seg: &str) -> Result<Vec<u8>, String> {
    JWT_B64
        .decode(seg.trim().trim_end_matches('='))
        .map_err(|e| format!("bad base64url segment: {e}"))
}

fn jwt_b64_encode(data: &[u8]) -> String {
    JWT_B64.encode(data)
}

/// HMAC-SHA256 (RFC 2104) — the JWT HS256 signature algorithm.
fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    use sha2::Digest as _;
    const BLOCK: usize = 64;
    let mut k = key.to_vec();
    if k.len() > BLOCK {
        k = sha2::Sha256::digest(&k).to_vec();
    }
    k.resize(BLOCK, 0);
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Vec::with_capacity(BLOCK + msg.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(msg);
    let inner = sha2::Sha256::digest(&inner);
    let mut outer = Vec::with_capacity(BLOCK + 32);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner);
    sha2::Sha256::digest(&outer).to_vec()
}

fn jwt_secret(key: &str, enc: KeyEncoding) -> Result<Vec<u8>, String> {
    let secret = key_bytes(key, enc).map_err(|e| format!("secret: {e}"))?;
    if secret.is_empty() {
        return Err("empty JWT secret".into());
    }
    Ok(secret)
}

/// Parse "header.payload.signature" (2 or 3 dot-separated segments).
fn jwt_parts(token: &[u8]) -> Result<(String, String, Option<String>), String> {
    let text = std::str::from_utf8(token).map_err(|_| "JWT input is not valid UTF-8 text")?;
    let text = text.trim();
    let mut it = text.split('.');
    let h = it.next().ok_or("empty JWT")?;
    let p = it.next().ok_or("JWT must be header.payload[.signature]")?;
    let sig = it.next();
    if it.next().is_some() {
        return Err("JWT has more than 3 dot-separated segments".into());
    }
    if h.is_empty() || p.is_empty() {
        return Err("JWT header or payload segment is empty".into());
    }
    Ok((
        h.to_string(),
        p.to_string(),
        sig.filter(|s| !s.is_empty()).map(str::to_string),
    ))
}

/// Base64url-decode + pretty-print a JSON segment; falls back to raw text.
fn jwt_pretty(seg: &str) -> String {
    match jwt_b64_decode(seg) {
        Ok(bytes) => serde_json::from_slice::<serde_json::Value>(&bytes)
            .map(|v| serde_json::to_string_pretty(&v).unwrap_or_default())
            .unwrap_or_else(|_| String::from_utf8_lossy(&bytes).to_string()),
        Err(e) => format!("<undecodable: {e}>"),
    }
}

fn jwt_decode(input: &[u8]) -> Result<Vec<u8>, String> {
    let (h, p, sig) = jwt_parts(input)?;
    let mut out = String::new();
    out.push_str("HEADER\n");
    out.push_str(&jwt_pretty(&h));
    out.push_str("\n\nPAYLOAD\n");
    out.push_str(&jwt_pretty(&p));
    out.push_str("\n\nSIGNATURE\n");
    match &sig {
        Some(s) => match jwt_b64_decode(s) {
            Ok(bytes) => out.push_str(&format!(
                "{} bytes, hex: {}",
                bytes.len(),
                hex::encode(&bytes)
            )),
            Err(e) => out.push_str(&format!("<undecodable: {e}>")),
        },
        None => out.push_str("<unsigned token (alg=none)>"),
    }
    Ok(out.into_bytes())
}

/// Sign `claims` (JSON text) as an HS256 JWT.
fn jwt_sign(claims: &[u8], secret: &[u8]) -> Result<Vec<u8>, String> {
    // Fail early if the claims are not JSON.
    serde_json::from_slice::<serde_json::Value>(claims)
        .map_err(|e| format!("claims are not valid JSON: {e}"))?;
    let header = br#"{"alg":"HS256","typ":"JWT"}"#;
    let signing_input = format!("{}.{}", jwt_b64_encode(header), jwt_b64_encode(claims));
    let sig = hmac_sha256(secret, signing_input.as_bytes());
    Ok(format!("{signing_input}.{}", jwt_b64_encode(&sig)).into_bytes())
}

/// Length-independent comparison for MAC verification.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// Verify an HS256 JWT; outputs the decoded claims on success.
fn jwt_verify(input: &[u8], secret: &[u8]) -> Result<Vec<u8>, String> {
    let (h, p, sig) = jwt_parts(input)?;
    let header_bytes = jwt_b64_decode(&h)?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| format!("JWT header is not valid JSON: {e}"))?;
    let alg = header
        .get("alg")
        .and_then(|v| v.as_str())
        .unwrap_or("<missing>");
    if !alg.eq_ignore_ascii_case("HS256") {
        return Err(format!(
            "JWT alg is '{alg}', only HS256 can be verified here"
        ));
    }
    let sig_bytes = sig
        .as_deref()
        .map(jwt_b64_decode)
        .transpose()?
        .ok_or("JWT has no signature segment")?;
    let signing_input = format!("{h}.{p}");
    let expected = hmac_sha256(secret, signing_input.as_bytes());
    if !constant_time_eq(&expected, &sig_bytes) {
        return Err("signature mismatch: wrong secret or tampered token".into());
    }
    let mut out = jwt_pretty(&p);
    out.push_str("\n\nsignature: valid (HS256)");
    Ok(out.into_bytes())
}

// ---------------------------------------------------------------- text ops

/// Percent-encode raw bytes: unreserved ASCII passes through, everything else
/// becomes `%XX`. Byte-oriented so binary intermediates survive the pipeline
/// (symmetric with `url_decode`).
fn percent_encode_strict(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * 3);
    for &b in bytes {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b)
            }
            _ => {
                out.push(b'%');
                out.extend_from_slice(format!("{b:02X}").as_bytes());
            }
        }
    }
    out
}

/// Percent-decode with '+' as space (application/x-www-form-urlencoded).
fn url_decode(bytes: &[u8]) -> Vec<u8> {
    let s = bytes;
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < s.len() => {
                let hi = (s[i + 1] as char).to_digit(16);
                let lo = (s[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

fn html_encode(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .map(|c| match c {
            '&' => "&amp;".into(),
            '<' => "&lt;".into(),
            '>' => "&gt;".into(),
            '"' => "&quot;".into(),
            '\'' => "&#39;".into(),
            c => c.to_string(),
        })
        .collect()
}

/// HTML entity decoding that tolerates bare `&`: a `&` that is not followed
/// by a well-formed `name;` / `#num;` sequence is emitted literally, matching
/// how real HTML parsers behave.
fn html_decode(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let s = String::from_utf8_lossy(bytes);
    let mut out = String::with_capacity(s.len());
    let mut rest = s.as_ref();
    while let Some(idx) = rest.find('&') {
        out.push_str(&rest[..idx]);
        let after = &rest[idx..];
        // Entity name: at most ~10 chars of [A-Za-z0-9#xX] immediately
        // followed by ';'. Otherwise treat the '&' literally.
        let body: String = after[1..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '#' || *c == 'x' || *c == 'X')
            .take(11)
            .collect();
        let terminated = body.len() < after.len() - 1
            && after[1..].starts_with(&body)
            && after[1 + body.len()..].starts_with(';');
        if body.is_empty() || !terminated {
            out.push('&');
            rest = &after[1..];
            continue;
        }
        let entity = body.as_str();
        let decoded = match entity {
            "amp" => "&",
            "lt" => "<",
            "gt" => ">",
            "quot" => "\"",
            "apos" => "'",
            "nbsp" => "\u{00a0}",
            other => {
                if let Some(num) = other.strip_prefix('#') {
                    let cp = num
                        .strip_prefix('x')
                        .or_else(|| num.strip_prefix('X'))
                        .map(|h| u32::from_str_radix(h, 16))
                        .unwrap_or_else(|| num.parse::<u32>())
                        .map_err(|_| "bad numeric entity")?;
                    &String::from(char::from_u32(cp).ok_or("bad codepoint")?)[..]
                } else {
                    // Unknown named entity: keep it verbatim.
                    out.push('&');
                    rest = &after[1..];
                    continue;
                }
            }
        };
        out.push_str(decoded);
        rest = &after[entity.len() + 2..];
    }
    out.push_str(rest);
    Ok(out.into_bytes())
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    fn step(kind: OpKind, key: &str, iv: &str) -> Step {
        Step {
            kind,
            enabled: true,
            params: StepParams {
                key: key.into(),
                iv: iv.into(),
                aad: String::new(),
                key_enc: KeyEncoding::Hex,
            },
        }
    }

    fn run(input: &str, steps: &[Step]) -> Vec<u8> {
        run_pipeline(input.as_bytes(), steps)
            .last()
            .map(|r| r.data.clone())
            .unwrap_or_default()
    }

    #[test]
    fn encoding_roundtrips() {
        let b64 = step(OpKind::Base64Encode, "", "");
        let b64d = step(OpKind::Base64Decode, "", "");
        assert_eq!(run("hello", &[b64, b64d]), b"hello".to_vec());

        let hx = step(OpKind::HexEncode, "", "");
        let hxd = step(OpKind::HexDecode, "", "");
        assert_eq!(run("héllo", &[hx, hxd]), "héllo".as_bytes().to_vec());

        let ue = step(OpKind::UrlEncode, "", "");
        let ud = step(OpKind::UrlDecode, "", "");
        assert_eq!(run("a b&c=d/", &[ue, ud]), b"a b&c=d/".to_vec());

        let he = step(OpKind::HtmlEncode, "", "");
        let hd = step(OpKind::HtmlDecode, "", "");
        assert_eq!(run("<a & 'b'>", &[he, hd]), b"<a & 'b'>".to_vec());
    }

    #[test]
    fn hashes() {
        assert_eq!(
            run("abc", &[step(OpKind::Md5, "", "")]),
            hex::decode("900150983cd24fb0d6963f7d28e17f72").unwrap()
        );
        assert_eq!(
            run("abc", &[step(OpKind::Sha256, "", "")]),
            hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .unwrap()
        );
    }

    #[test]
    fn aes_ecb_fips197() {
        // FIPS-197 C.1: key 000102..0f, pt 00112233..eeff -> 69c4e0d8...
        let s = step(
            OpKind::AesCrypt {
                enc: true,
                mode: BlockMode::Ecb,
            },
            "000102030405060708090a0b0c0d0e0f",
            "",
        );
        let pt: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let ct = run_pipeline(&pt, &[s]).remove(0).data;
        assert_eq!(
            &ct[..16],
            &hex::decode("69c4e0d86a7b0430d8cdb78070b4c55a").unwrap()[..]
        );

        // Roundtrip through the pipeline with binary-safe bytes.
        let mut steps = vec![Step::new(OpKind::AesCrypt {
            enc: true,
            mode: BlockMode::Ecb,
        })];
        steps[0].params.key = "00112233445566778899aabbccddeeff".into();
        steps[0].params.key_enc = KeyEncoding::Utf8;
        let enc = run("secret message!!", &steps);
        steps[0].kind = OpKind::AesCrypt {
            enc: false,
            mode: BlockMode::Ecb,
        };
        let pt = run_pipeline(&enc, &steps).remove(0).data;
        assert_eq!(pt, b"secret message!!".to_vec());
    }

    #[test]
    fn aes_cbc_roundtrip_and_error() {
        let mut steps = vec![
            Step::new(OpKind::AesCrypt {
                enc: true,
                mode: BlockMode::Cbc,
            }),
            Step::new(OpKind::AesCrypt {
                enc: false,
                mode: BlockMode::Cbc,
            }),
        ];
        for s in &mut steps {
            s.params.key = "2b7e151628aed2a6abf7158809cf4f3c".into();
            s.params.iv = "000102030405060708090a0b0c0d0e0f".into();
        }
        assert_eq!(
            run("attack at dawn!!", &steps),
            b"attack at dawn!!".to_vec()
        );

        steps[1].params.key = "00112233445566778899aabbccddeeff".into();
        let res = run_pipeline(b"attack at dawn!!", &steps);
        assert!(res[1].error.is_some());
    }

    #[test]
    fn des_vectors() {
        // Classic DES vector: key 133457799BBCDFF1, pt 0123456789ABCDEF
        // -> ct 85E813540F0AB405.
        let s = step(
            OpKind::DesCrypt {
                enc: true,
                triple: false,
                mode: BlockMode::Ecb,
            },
            "133457799bbcdff1",
            "",
        );
        let ct = run_pipeline(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef], &[s])
            .remove(0)
            .data;
        assert_eq!(&ct[..8], &hex::decode("85e813540f0ab405").unwrap()[..]);

        let mut steps = vec![
            Step::new(OpKind::DesCrypt {
                enc: true,
                triple: true,
                mode: BlockMode::Cbc,
            }),
            Step::new(OpKind::DesCrypt {
                enc: false,
                triple: true,
                mode: BlockMode::Cbc,
            }),
        ];
        for s in &mut steps {
            s.params.key = "0123456789abcdef0123456789abcdef0123456789abcdef".into();
            s.params.iv = "0123456789abcdef".into();
        }
        assert_eq!(run("8 bytes!!", &steps), b"8 bytes!!".to_vec());
    }

    #[test]
    fn sm4_vector() {
        // GB/T 32907 sample: key = pt = 0123456789abcdeffedcba9876543210
        // -> first ECB block 681edf34d206965e86b3e94f536e4246.
        let s = step(
            OpKind::Sm4Crypt {
                enc: true,
                mode: BlockMode::Ecb,
            },
            "0123456789abcdeffedcba9876543210",
            "",
        );
        let pt: [u8; 16] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let ct = run_pipeline(&pt, &[s]).remove(0).data;
        assert_eq!(
            &ct[..16],
            &hex::decode("681edf34d206965e86b3e94f536e4246").unwrap()[..]
        );
    }

    #[test]
    fn rc4_vector() {
        // Well-known RC4 test vector: key "Key", pt "Plaintext"
        // -> bbf316e8d940af0ad3.
        let mut s = step(OpKind::Rc4Crypt, "4b6579", "");
        s.params.key_enc = KeyEncoding::Hex;
        let ct = run("Plaintext", &[s]);
        assert_eq!(ct, hex::decode("bbf316e8d940af0ad3").unwrap());
    }

    #[test]
    fn aes_gcm_roundtrip_and_tamper() {
        let mut steps = vec![
            Step::new(OpKind::AesGcmCrypt { enc: true }),
            Step::new(OpKind::HexEncode),
            Step::new(OpKind::HexDecode),
            Step::new(OpKind::AesGcmCrypt { enc: false }),
        ];
        for s in &mut steps {
            s.params.key = "feffe9928665731c6d6a8f9467308308".into();
            s.params.iv = "cafebabefacedbaddecaf888".into();
        }
        steps[0].params.aad = "feedfacedeadbeef".into();
        steps[3].params.aad = "feedfacedeadbeef".into();
        assert_eq!(
            run("gcm test payload", &steps),
            b"gcm test payload".to_vec()
        );

        // Tamper with the ciphertext via an XOR step in the middle: hex toggle
        // is not enough — flip a byte by re-encrypting with a wrong key instead.
        steps[3].params.key = "00112233445566778899aabbccddeeff".into();
        let res = run_pipeline(b"gcm test payload", &steps);
        assert!(res.last().unwrap().error.is_some());
    }

    #[test]
    fn key_error_paths() {
        let res = run_pipeline(
            b"x",
            &[step(
                OpKind::AesCrypt {
                    enc: true,
                    mode: BlockMode::Ecb,
                },
                "abcd",
                "",
            )],
        );
        assert!(res[0].error.as_ref().unwrap().contains("16/24/32"));

        let res = run_pipeline(
            b"x",
            &[step(
                OpKind::AesCrypt {
                    enc: true,
                    mode: BlockMode::Cbc,
                },
                "00112233445566778899aabbccddeeff",
                "0001", // too short IV
            )],
        );
        assert!(res[0].error.as_ref().unwrap().contains("IV"));

        let mut s = step(OpKind::HexDecode, "", "");
        s.params.key = String::new();
        let res = run_pipeline(b"zzzz", &[s]); // invalid hex digits
        assert!(res[0].error.is_some());
    }

    #[test]
    fn disabled_and_failed_steps() {
        let steps = vec![
            Step {
                kind: OpKind::Base64Encode,
                enabled: false,
                params: StepParams::default(),
            },
            step(
                OpKind::AesCrypt {
                    enc: true,
                    mode: BlockMode::Ecb,
                },
                "bad",
                "",
            ),
            Step::new(OpKind::Base64Encode),
        ];
        let res = run_pipeline(b"hi", &steps);
        assert!(res[0].error.is_none());
        assert_eq!(res[0].data, b"hi");
        assert!(res[1].error.is_some());
        assert!(res[2].error.as_ref().unwrap().contains("skipped"));
        assert_eq!(res[2].data, b"hi");
    }
}

#[cfg(test)]
mod jwt_sm3_tests {
    use super::*;

    fn run_one(input: &[u8], kind: OpKind, key: &str) -> Result<Vec<u8>, String> {
        let step = Step {
            kind,
            enabled: true,
            params: StepParams {
                key: key.to_string(),
                key_enc: KeyEncoding::Utf8,
                ..Default::default()
            },
        };
        exec(&step, input)
    }

    #[test]
    fn sm3_digest_length_and_stability() {
        let d = run_one(b"abc", OpKind::Sm3, "").unwrap();
        assert_eq!(d.len(), 32, "SM3 digest must be 256 bits");
        let d2 = run_one(b"abc", OpKind::Sm3, "").unwrap();
        assert_eq!(d, d2);
        // SM3 must differ from SHA-256.
        let sha = run_one(b"abc", OpKind::Sha256, "").unwrap();
        assert_ne!(d, sha);
    }

    #[test]
    fn jwt_sign_verify_roundtrip() {
        let claims = br#"{"sub":"admin","role":"tester","exp":1700000000}"#;
        let token = run_one(claims, OpKind::JwtSign, "s3cret").unwrap();
        let token_str = String::from_utf8(token.clone()).unwrap();
        assert_eq!(token_str.split('.').count(), 3);

        // Verify with the right secret returns the claims.
        let verified = run_one(&token, OpKind::JwtVerify, "s3cret").unwrap();
        let text = String::from_utf8(verified).unwrap();
        assert!(text.contains("\"admin\""));
        assert!(text.contains("signature: valid (HS256)"));

        // Wrong secret fails.
        assert!(run_one(&token, OpKind::JwtVerify, "wrong").is_err());
    }

    #[test]
    fn jwt_decode_shows_header_payload_signature() {
        let token = run_one(br#"{"sub":"admin"}"#, OpKind::JwtSign, "k").unwrap();
        let decoded = run_one(&token, OpKind::JwtDecode, "").unwrap();
        let text = String::from_utf8(decoded).unwrap();
        assert!(text.contains("HEADER") && text.contains("HS256"));
        assert!(text.contains("PAYLOAD") && text.contains("\"sub\""));
        assert!(text.contains("SIGNATURE") && text.contains("32 bytes"));
    }

    #[test]
    fn jwt_verify_rejects_non_hs256() {
        // alg=none unsigned-style token.
        let forged = format!(
            "{}.{}.{}",
            JWT_B64.encode(br#"{"alg":"none","typ":"JWT"}"#),
            JWT_B64.encode(br#"{"sub":"admin"}"#),
            JWT_B64.encode(b"fakesig")
        );
        assert!(run_one(forged.as_bytes(), OpKind::JwtVerify, "k").is_err());
    }

    #[test]
    fn hmac_sha256_known_vector() {
        // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?".
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex::encode(&mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }
}

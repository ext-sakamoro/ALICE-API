//! Request / Response Transform — リクエスト・レスポンス変換
//!
//! ゲートウェイ通過時のヘッダー操作、パス書換、ステータスコード変換。
//! 固定サイズバッファ、`no_std` 対応。
//!
//! Author: Moroya Sakamoto

// ============================================================================
// Header Operation — ヘッダー操作
// ============================================================================

/// ヘッダー操作の種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderOp {
    /// ヘッダーを追加（既存でも追加）。
    Add,
    /// ヘッダーを設定（既存なら上書き）。
    Set,
    /// ヘッダーを削除。
    Remove,
}

/// 単一ヘッダー変換ルール。
///
/// 固定サイズバッファでヘッダー名と値を保持。
#[derive(Debug, Clone, Copy)]
pub struct HeaderRule {
    /// ヘッダー名（最大63バイト + null終端）。
    name: [u8; 64],
    /// ヘッダー名の長さ。
    name_len: u8,
    /// ヘッダー値（最大127バイト + null終端）。
    value: [u8; 128],
    /// ヘッダー値の長さ。
    value_len: u8,
    /// 操作種別。
    pub op: HeaderOp,
}

impl HeaderRule {
    /// 新しいヘッダールールを作成。
    #[must_use]
    pub fn new(op: HeaderOp, name: &[u8], value: &[u8]) -> Self {
        let mut rule = Self {
            name: [0u8; 64],
            name_len: 0,
            value: [0u8; 128],
            value_len: 0,
            op,
        };
        let n_len = name.len().min(63);
        rule.name[..n_len].copy_from_slice(&name[..n_len]);
        rule.name_len = n_len as u8;

        let v_len = value.len().min(127);
        rule.value[..v_len].copy_from_slice(&value[..v_len]);
        rule.value_len = v_len as u8;

        rule
    }

    /// ヘッダー名。
    #[inline]
    #[must_use]
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    /// ヘッダー値。
    #[inline]
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value[..self.value_len as usize]
    }
}

// ============================================================================
// Path Transform — パス変換
// ============================================================================

/// パス変換の種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathOp {
    /// プレフィックスを付加。
    AddPrefix,
    /// プレフィックスを除去。
    StripPrefix,
    /// パスを完全置換。
    Replace,
}

/// パス変換ルール。
#[derive(Debug, Clone, Copy)]
pub struct PathRule {
    /// パターン（最大255バイト）。
    pattern: [u8; 256],
    /// パターンの長さ。
    pattern_len: u16,
    /// 置換先（`Replace` 時のみ使用）。
    replacement: [u8; 256],
    /// 置換先の長さ。
    replacement_len: u16,
    /// 操作種別。
    pub op: PathOp,
}

impl PathRule {
    /// プレフィックス付加ルールを作成。
    #[must_use]
    pub fn add_prefix(prefix: &[u8]) -> Self {
        let mut rule = Self {
            pattern: [0u8; 256],
            pattern_len: 0,
            replacement: [0u8; 256],
            replacement_len: 0,
            op: PathOp::AddPrefix,
        };
        let len = prefix.len().min(255);
        rule.pattern[..len].copy_from_slice(&prefix[..len]);
        rule.pattern_len = len as u16;
        rule
    }

    /// プレフィックス除去ルールを作成。
    #[must_use]
    pub fn strip_prefix(prefix: &[u8]) -> Self {
        let mut rule = Self {
            pattern: [0u8; 256],
            pattern_len: 0,
            replacement: [0u8; 256],
            replacement_len: 0,
            op: PathOp::StripPrefix,
        };
        let len = prefix.len().min(255);
        rule.pattern[..len].copy_from_slice(&prefix[..len]);
        rule.pattern_len = len as u16;
        rule
    }

    /// パス完全置換ルールを作成。
    #[must_use]
    pub fn replace(from: &[u8], to: &[u8]) -> Self {
        let mut rule = Self {
            pattern: [0u8; 256],
            pattern_len: 0,
            replacement: [0u8; 256],
            replacement_len: 0,
            op: PathOp::Replace,
        };
        let f_len = from.len().min(255);
        rule.pattern[..f_len].copy_from_slice(&from[..f_len]);
        rule.pattern_len = f_len as u16;

        let t_len = to.len().min(255);
        rule.replacement[..t_len].copy_from_slice(&to[..t_len]);
        rule.replacement_len = t_len as u16;
        rule
    }

    /// パターン。
    #[inline]
    #[must_use]
    pub fn pattern(&self) -> &[u8] {
        &self.pattern[..self.pattern_len as usize]
    }

    /// パスを変換。結果を `out` に書き込み、書き込んだバイト数を返す。
    ///
    /// 変換不要の場合は `None`。
    pub fn apply(&self, path: &[u8], out: &mut [u8]) -> Option<usize> {
        match self.op {
            PathOp::AddPrefix => {
                let prefix = self.pattern();
                let total = prefix.len() + path.len();
                if total > out.len() {
                    return None;
                }
                out[..prefix.len()].copy_from_slice(prefix);
                out[prefix.len()..total].copy_from_slice(path);
                Some(total)
            }
            PathOp::StripPrefix => {
                let prefix = self.pattern();
                if path.len() >= prefix.len() && &path[..prefix.len()] == prefix {
                    let remaining = &path[prefix.len()..];
                    if remaining.is_empty() {
                        // "/" を返す
                        if out.is_empty() {
                            return None;
                        }
                        out[0] = b'/';
                        Some(1)
                    } else {
                        let len = remaining.len();
                        if len > out.len() {
                            return None;
                        }
                        out[..len].copy_from_slice(remaining);
                        Some(len)
                    }
                } else {
                    None
                }
            }
            PathOp::Replace => {
                let from = self.pattern();
                if path == from {
                    let to = &self.replacement[..self.replacement_len as usize];
                    if to.len() > out.len() {
                        return None;
                    }
                    out[..to.len()].copy_from_slice(to);
                    Some(to.len())
                } else {
                    None
                }
            }
        }
    }
}

// ============================================================================
// Request Transform — リクエスト変換
// ============================================================================

/// リクエスト変換パイプライン。
///
/// 最大16個のヘッダールールと1個のパスルールを保持。
pub struct RequestTransform {
    /// ヘッダー変換ルール。
    header_rules: [Option<HeaderRule>; 16],
    /// ヘッダールール数。
    header_count: usize,
    /// パス変換ルール（最大1つ）。
    path_rule: Option<PathRule>,
}

impl RequestTransform {
    /// 空の変換を作成。
    #[must_use]
    pub const fn new() -> Self {
        Self {
            header_rules: [None; 16],
            header_count: 0,
            path_rule: None,
        }
    }

    /// ヘッダールールを追加。
    ///
    /// バッファが満杯の場合は `false`。
    pub const fn add_header_rule(&mut self, rule: HeaderRule) -> bool {
        if self.header_count >= 16 {
            return false;
        }
        self.header_rules[self.header_count] = Some(rule);
        self.header_count += 1;
        true
    }

    /// パスルールを設定。
    pub const fn set_path_rule(&mut self, rule: PathRule) {
        self.path_rule = Some(rule);
    }

    /// ヘッダールール数。
    #[inline]
    #[must_use]
    pub const fn header_rule_count(&self) -> usize {
        self.header_count
    }

    /// ヘッダールールのイテレータ。
    pub fn header_rules(&self) -> impl Iterator<Item = &HeaderRule> {
        self.header_rules[..self.header_count]
            .iter()
            .filter_map(|r| r.as_ref())
    }

    /// パスルールの参照。
    #[inline]
    #[must_use]
    pub const fn path_rule(&self) -> Option<&PathRule> {
        self.path_rule.as_ref()
    }

    /// パスを変換。変換不要なら `None`。
    pub fn transform_path(&self, path: &[u8], out: &mut [u8]) -> Option<usize> {
        self.path_rule.as_ref()?.apply(path, out)
    }

    /// ルールをクリア。
    pub fn clear(&mut self) {
        self.header_count = 0;
        for slot in &mut self.header_rules {
            *slot = None;
        }
        self.path_rule = None;
    }
}

impl Default for RequestTransform {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Response Transform — レスポンス変換
// ============================================================================

/// ステータスコード変換ルール。
#[derive(Debug, Clone, Copy)]
pub struct StatusRewrite {
    /// 元のステータスコード（0 = ワイルドカード）。
    pub from: u16,
    /// 変換先ステータスコード。
    pub to: u16,
}

/// レスポンス変換パイプライン。
///
/// 最大16個のヘッダールールと最大4個のステータス書換ルール。
pub struct ResponseTransform {
    /// ヘッダー変換ルール。
    header_rules: [Option<HeaderRule>; 16],
    /// ヘッダールール数。
    header_count: usize,
    /// ステータスコード書換ルール。
    status_rewrites: [Option<StatusRewrite>; 4],
    /// ステータスルール数。
    status_count: usize,
}

impl ResponseTransform {
    /// 空の変換を作成。
    #[must_use]
    pub const fn new() -> Self {
        Self {
            header_rules: [None; 16],
            header_count: 0,
            status_rewrites: [None; 4],
            status_count: 0,
        }
    }

    /// ヘッダールールを追加。
    pub const fn add_header_rule(&mut self, rule: HeaderRule) -> bool {
        if self.header_count >= 16 {
            return false;
        }
        self.header_rules[self.header_count] = Some(rule);
        self.header_count += 1;
        true
    }

    /// ステータス書換ルールを追加。
    pub const fn add_status_rewrite(&mut self, rewrite: StatusRewrite) -> bool {
        if self.status_count >= 4 {
            return false;
        }
        self.status_rewrites[self.status_count] = Some(rewrite);
        self.status_count += 1;
        true
    }

    /// ステータスコードを変換。変換不要なら元のコードを返す。
    #[must_use]
    pub fn rewrite_status(&self, status: u16) -> u16 {
        for rule in self.status_rewrites[..self.status_count].iter().flatten() {
            if rule.from == status || rule.from == 0 {
                return rule.to;
            }
        }
        status
    }

    /// ヘッダールール数。
    #[inline]
    #[must_use]
    pub const fn header_rule_count(&self) -> usize {
        self.header_count
    }

    /// ヘッダールールのイテレータ。
    pub fn header_rules(&self) -> impl Iterator<Item = &HeaderRule> {
        self.header_rules[..self.header_count]
            .iter()
            .filter_map(|r| r.as_ref())
    }

    /// ルールをクリア。
    pub fn clear(&mut self) {
        self.header_count = 0;
        for slot in &mut self.header_rules {
            *slot = None;
        }
        self.status_count = 0;
        for slot in &mut self.status_rewrites {
            *slot = None;
        }
    }
}

impl Default for ResponseTransform {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- HeaderRule ---

    #[test]
    fn header_rule_add() {
        let rule = HeaderRule::new(HeaderOp::Add, b"X-Request-Id", b"abc123");
        assert_eq!(rule.name(), b"X-Request-Id");
        assert_eq!(rule.value(), b"abc123");
        assert_eq!(rule.op, HeaderOp::Add);
    }

    #[test]
    fn header_rule_remove() {
        let rule = HeaderRule::new(HeaderOp::Remove, b"Cookie", b"");
        assert_eq!(rule.name(), b"Cookie");
        assert_eq!(rule.op, HeaderOp::Remove);
    }

    #[test]
    fn header_rule_truncation() {
        let long_name = [b'A'; 100];
        let rule = HeaderRule::new(HeaderOp::Set, &long_name, b"val");
        assert_eq!(rule.name().len(), 63);
    }

    // --- PathRule ---

    #[test]
    fn path_add_prefix() {
        let rule = PathRule::add_prefix(b"/api/v2");
        let mut out = [0u8; 256];
        let len = rule.apply(b"/users", &mut out).unwrap();
        assert_eq!(&out[..len], b"/api/v2/users");
    }

    #[test]
    fn path_strip_prefix() {
        let rule = PathRule::strip_prefix(b"/api/v1");
        let mut out = [0u8; 256];
        let len = rule.apply(b"/api/v1/users", &mut out).unwrap();
        assert_eq!(&out[..len], b"/users");
    }

    #[test]
    fn path_strip_prefix_exact() {
        let rule = PathRule::strip_prefix(b"/api");
        let mut out = [0u8; 256];
        let len = rule.apply(b"/api", &mut out).unwrap();
        assert_eq!(&out[..len], b"/");
    }

    #[test]
    fn path_strip_prefix_no_match() {
        let rule = PathRule::strip_prefix(b"/api");
        let mut out = [0u8; 256];
        assert!(rule.apply(b"/other", &mut out).is_none());
    }

    #[test]
    fn path_replace() {
        let rule = PathRule::replace(b"/old-path", b"/new-path");
        let mut out = [0u8; 256];
        let len = rule.apply(b"/old-path", &mut out).unwrap();
        assert_eq!(&out[..len], b"/new-path");
    }

    #[test]
    fn path_replace_no_match() {
        let rule = PathRule::replace(b"/old-path", b"/new-path");
        let mut out = [0u8; 256];
        assert!(rule.apply(b"/other-path", &mut out).is_none());
    }

    // --- RequestTransform ---

    #[test]
    fn request_transform_empty() {
        let rt = RequestTransform::new();
        assert_eq!(rt.header_rule_count(), 0);
        assert!(rt.path_rule().is_none());
    }

    #[test]
    fn request_transform_add_headers() {
        let mut rt = RequestTransform::new();
        assert!(rt.add_header_rule(HeaderRule::new(
            HeaderOp::Add,
            b"X-Forwarded-For",
            b"10.0.0.1"
        )));
        assert!(rt.add_header_rule(HeaderRule::new(HeaderOp::Set, b"Host", b"backend.local")));
        assert_eq!(rt.header_rule_count(), 2);
    }

    #[test]
    fn request_transform_header_limit() {
        let mut rt = RequestTransform::new();
        for i in 0..16 {
            let name = [b'A' + (i as u8 % 26)];
            assert!(rt.add_header_rule(HeaderRule::new(HeaderOp::Add, &name, b"v")));
        }
        assert!(!rt.add_header_rule(HeaderRule::new(HeaderOp::Add, b"X", b"v")));
    }

    #[test]
    fn request_transform_path() {
        let mut rt = RequestTransform::new();
        rt.set_path_rule(PathRule::add_prefix(b"/backend"));
        let mut out = [0u8; 256];
        let len = rt.transform_path(b"/resource", &mut out).unwrap();
        assert_eq!(&out[..len], b"/backend/resource");
    }

    #[test]
    fn request_transform_no_path_rule() {
        let rt = RequestTransform::new();
        let mut out = [0u8; 256];
        assert!(rt.transform_path(b"/resource", &mut out).is_none());
    }

    #[test]
    fn request_transform_clear() {
        let mut rt = RequestTransform::new();
        rt.add_header_rule(HeaderRule::new(HeaderOp::Add, b"X", b"y"));
        rt.set_path_rule(PathRule::add_prefix(b"/a"));
        rt.clear();
        assert_eq!(rt.header_rule_count(), 0);
        assert!(rt.path_rule().is_none());
    }

    #[test]
    fn request_transform_default() {
        let rt = RequestTransform::default();
        assert_eq!(rt.header_rule_count(), 0);
    }

    #[test]
    fn request_transform_iterate_headers() {
        let mut rt = RequestTransform::new();
        rt.add_header_rule(HeaderRule::new(HeaderOp::Add, b"A", b"1"));
        rt.add_header_rule(HeaderRule::new(HeaderOp::Set, b"B", b"2"));
        let rules: Vec<_> = rt.header_rules().collect();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].name(), b"A");
        assert_eq!(rules[1].name(), b"B");
    }

    // --- ResponseTransform ---

    #[test]
    fn response_transform_empty() {
        let rt = ResponseTransform::new();
        assert_eq!(rt.header_rule_count(), 0);
        assert_eq!(rt.rewrite_status(200), 200);
    }

    #[test]
    fn response_status_rewrite() {
        let mut rt = ResponseTransform::new();
        rt.add_status_rewrite(StatusRewrite { from: 404, to: 200 });
        assert_eq!(rt.rewrite_status(404), 200);
        assert_eq!(rt.rewrite_status(500), 500);
    }

    #[test]
    fn response_status_wildcard() {
        let mut rt = ResponseTransform::new();
        rt.add_status_rewrite(StatusRewrite { from: 0, to: 503 });
        assert_eq!(rt.rewrite_status(200), 503);
        assert_eq!(rt.rewrite_status(404), 503);
    }

    #[test]
    fn response_status_rewrite_limit() {
        let mut rt = ResponseTransform::new();
        for i in 0..4 {
            assert!(rt.add_status_rewrite(StatusRewrite {
                from: 400 + i,
                to: 200,
            }));
        }
        assert!(!rt.add_status_rewrite(StatusRewrite { from: 500, to: 200 }));
    }

    #[test]
    fn response_transform_headers() {
        let mut rt = ResponseTransform::new();
        rt.add_header_rule(HeaderRule::new(HeaderOp::Add, b"X-Frame-Options", b"DENY"));
        assert_eq!(rt.header_rule_count(), 1);
        let rules: Vec<_> = rt.header_rules().collect();
        assert_eq!(rules[0].name(), b"X-Frame-Options");
    }

    #[test]
    fn response_transform_clear() {
        let mut rt = ResponseTransform::new();
        rt.add_header_rule(HeaderRule::new(HeaderOp::Add, b"X", b"y"));
        rt.add_status_rewrite(StatusRewrite { from: 404, to: 200 });
        rt.clear();
        assert_eq!(rt.header_rule_count(), 0);
        assert_eq!(rt.rewrite_status(404), 404);
    }

    #[test]
    fn response_transform_default() {
        let rt = ResponseTransform::default();
        assert_eq!(rt.header_rule_count(), 0);
    }

    // --- HeaderOp eq ---

    #[test]
    fn header_op_eq() {
        assert_eq!(HeaderOp::Add, HeaderOp::Add);
        assert_ne!(HeaderOp::Add, HeaderOp::Set);
        assert_ne!(HeaderOp::Set, HeaderOp::Remove);
    }

    // --- PathOp eq ---

    #[test]
    fn path_op_eq() {
        assert_eq!(PathOp::AddPrefix, PathOp::AddPrefix);
        assert_ne!(PathOp::StripPrefix, PathOp::Replace);
    }
}

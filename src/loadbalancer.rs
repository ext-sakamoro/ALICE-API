//! ロードバランシングアルゴリズム
//!
//! Weighted Round Robin, Least Connections, Consistent Hash (Sticky Session) の3方式。
//! すべて `no_std` 互換、ヒープ不使用。

// ============================================================================
// 共通型
// ============================================================================

/// バックエンドの重み・接続数を管理するエントリ。
#[derive(Debug, Clone, Copy)]
pub struct BackendEntry {
    /// バックエンドID。
    pub id: u32,
    /// 重み（Weighted Round Robin用）。
    pub weight: u32,
    /// 現在の有効重み（WRR内部状態）。
    current_weight: i64,
    /// アクティブ接続数（Least Connections用）。
    pub active_connections: u32,
    /// 健全フラグ。
    pub healthy: bool,
}

impl BackendEntry {
    /// 新しいバックエンドエントリを作成。
    #[must_use]
    pub const fn new(id: u32, weight: u32) -> Self {
        Self {
            id,
            weight,
            current_weight: 0,
            active_connections: 0,
            healthy: true,
        }
    }
}

// ============================================================================
// Weighted Round Robin
// ============================================================================

/// Smooth Weighted Round Robin (nginx方式)。
///
/// 各バックエンドに `effective_weight` を持ち、選択のたびに自身の weight を加算、
/// 選択されたバックエンドは `total_weight` を減算。均等に分散される。
pub struct WeightedRoundRobin<const N: usize> {
    backends: [Option<BackendEntry>; N],
    count: usize,
}

impl<const N: usize> Default for WeightedRoundRobin<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> WeightedRoundRobin<N> {
    const NONE: Option<BackendEntry> = None;

    /// 空のWRRを作成。
    #[must_use]
    pub const fn new() -> Self {
        Self {
            backends: [Self::NONE; N],
            count: 0,
        }
    }

    /// バックエンドを追加。
    pub const fn add(&mut self, entry: BackendEntry) -> bool {
        if self.count >= N {
            return false;
        }
        self.backends[self.count] = Some(entry);
        self.count += 1;
        true
    }

    /// 次のバックエンドを選択（Smooth WRR）。
    pub fn select(&mut self) -> Option<u32> {
        if self.count == 0 {
            return None;
        }

        let mut total_weight: i64 = 0;
        let mut best_idx: Option<usize> = None;
        let mut best_weight: i64 = i64::MIN;

        // 有効な（healthy）バックエンドの total_weight を計算し、
        // current_weight に weight を加算
        for i in 0..self.count {
            if let Some(ref mut entry) = self.backends[i] {
                if !entry.healthy {
                    continue;
                }
                let w = entry.weight as i64;
                total_weight += w;
                entry.current_weight += w;

                if entry.current_weight > best_weight {
                    best_weight = entry.current_weight;
                    best_idx = Some(i);
                }
            }
        }

        // 選択されたバックエンドの current_weight から total_weight を減算
        let idx = best_idx?;
        if let Some(ref mut entry) = self.backends[idx] {
            entry.current_weight -= total_weight;
            Some(entry.id)
        } else {
            None
        }
    }

    /// バックエンド数。
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// 空か。
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// 健全フラグ設定。
    pub fn set_healthy(&mut self, id: u32, healthy: bool) {
        for entry in self.backends[..self.count].iter_mut().flatten() {
            if entry.id == id {
                entry.healthy = healthy;
                if !healthy {
                    entry.current_weight = 0;
                }
                break;
            }
        }
    }
}

// ============================================================================
// Least Connections
// ============================================================================

/// Least Connections ロードバランサー。
///
/// アクティブ接続数が最小のバックエンドを選択。
/// 同数の場合は重みの大きいほうを優先。
pub struct LeastConnections<const N: usize> {
    backends: [Option<BackendEntry>; N],
    count: usize,
}

impl<const N: usize> Default for LeastConnections<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> LeastConnections<N> {
    const NONE: Option<BackendEntry> = None;

    /// 空の Least Connections バランサーを作成。
    #[must_use]
    pub const fn new() -> Self {
        Self {
            backends: [Self::NONE; N],
            count: 0,
        }
    }

    /// バックエンドを追加。
    pub const fn add(&mut self, entry: BackendEntry) -> bool {
        if self.count >= N {
            return false;
        }
        self.backends[self.count] = Some(entry);
        self.count += 1;
        true
    }

    /// 次のバックエンドを選択（接続数最小、同数なら重み最大）。
    #[must_use]
    pub fn select(&self) -> Option<u32> {
        let mut best_id: Option<u32> = None;
        let mut best_conn = u32::MAX;
        let mut best_weight = 0u32;

        for entry in self.backends[..self.count].iter().flatten() {
            if !entry.healthy {
                continue;
            }
            if entry.active_connections < best_conn
                || (entry.active_connections == best_conn && entry.weight > best_weight)
            {
                best_conn = entry.active_connections;
                best_weight = entry.weight;
                best_id = Some(entry.id);
            }
        }

        best_id
    }

    /// 接続開始を記録。
    pub fn connect(&mut self, id: u32) {
        for entry in self.backends[..self.count].iter_mut().flatten() {
            if entry.id == id {
                entry.active_connections += 1;
                break;
            }
        }
    }

    /// 接続終了を記録。
    pub fn disconnect(&mut self, id: u32) {
        for entry in self.backends[..self.count].iter_mut().flatten() {
            if entry.id == id {
                entry.active_connections = entry.active_connections.saturating_sub(1);
                break;
            }
        }
    }

    /// 健全フラグ設定。
    pub fn set_healthy(&mut self, id: u32, healthy: bool) {
        for entry in self.backends[..self.count].iter_mut().flatten() {
            if entry.id == id {
                entry.healthy = healthy;
                break;
            }
        }
    }

    /// バックエンド数。
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// 空か。
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// ============================================================================
// Consistent Hash (Sticky Session)
// ============================================================================

/// Consistent Hash によるスティッキーセッション。
///
/// クライアント識別子（IP, Cookie等）のハッシュで常に同じバックエンドに振り分け。
/// Jump Consistent Hash を使用（O(1) メモリ、O(ln n) 計算）。
pub struct ConsistentHash<const N: usize> {
    backends: [Option<BackendEntry>; N],
    count: usize,
    /// 健全なバックエンドのIDリスト（キャッシュ）。
    healthy_ids: [u32; N],
    healthy_count: usize,
}

impl<const N: usize> Default for ConsistentHash<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> ConsistentHash<N> {
    const NONE: Option<BackendEntry> = None;

    /// 空の Consistent Hash バランサーを作成。
    #[must_use]
    pub const fn new() -> Self {
        Self {
            backends: [Self::NONE; N],
            count: 0,
            healthy_ids: [0; N],
            healthy_count: 0,
        }
    }

    /// バックエンドを追加。
    pub fn add(&mut self, entry: BackendEntry) -> bool {
        if self.count >= N {
            return false;
        }
        let id = entry.id;
        self.backends[self.count] = Some(entry);
        self.count += 1;
        // 健全リスト再構築
        self.rebuild_healthy();
        let _ = id;
        true
    }

    /// 健全リストを再構築。
    fn rebuild_healthy(&mut self) {
        self.healthy_count = 0;
        for entry in self.backends[..self.count].iter().flatten() {
            if entry.healthy && self.healthy_count < N {
                self.healthy_ids[self.healthy_count] = entry.id;
                self.healthy_count += 1;
            }
        }
    }

    /// クライアントハッシュからバックエンドを選択（Jump Consistent Hash）。
    #[must_use]
    pub fn select(&self, client_hash: u64) -> Option<u32> {
        if self.healthy_count == 0 {
            return None;
        }
        let bucket = jump_consistent_hash(client_hash, self.healthy_count as u32);
        Some(self.healthy_ids[bucket as usize])
    }

    /// 健全フラグ設定。
    pub fn set_healthy(&mut self, id: u32, healthy: bool) {
        for entry in self.backends[..self.count].iter_mut().flatten() {
            if entry.id == id {
                entry.healthy = healthy;
                break;
            }
        }
        self.rebuild_healthy();
    }

    /// 健全なバックエンド数。
    #[inline]
    #[must_use]
    pub const fn healthy_count(&self) -> usize {
        self.healthy_count
    }

    /// バックエンド数。
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// 空か。
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// Jump Consistent Hash (Lamping & Veach, 2014)。
///
/// O(ln n) 時間、O(1) メモリ。バケット数変更時の再配置が最小。
#[inline]
#[must_use]
pub fn jump_consistent_hash(mut key: u64, num_buckets: u32) -> u32 {
    if num_buckets <= 1 {
        return 0;
    }

    let mut b: i64 = -1;
    let mut j: i64 = 0;

    while j < num_buckets as i64 {
        b = j;
        key = key.wrapping_mul(2_862_933_555_777_941_757).wrapping_add(1);
        j = ((b.wrapping_add(1)) as f64
            * (((1i64 << 31) as f64) / ((key >> 33).wrapping_add(1) as f64))) as i64;
    }

    b as u32
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Weighted Round Robin ---

    #[test]
    fn wrr_basic_equal_weights() {
        let mut wrr = WeightedRoundRobin::<4>::new();
        wrr.add(BackendEntry::new(1, 1));
        wrr.add(BackendEntry::new(2, 1));
        wrr.add(BackendEntry::new(3, 1));

        // 3つのバックエンドが均等に選ばれる
        let mut counts = [0u32; 4]; // id 1,2,3
        for _ in 0..30 {
            let id = wrr.select().unwrap();
            counts[id as usize] += 1;
        }
        assert_eq!(counts[1], 10);
        assert_eq!(counts[2], 10);
        assert_eq!(counts[3], 10);
    }

    #[test]
    fn wrr_weighted_distribution() {
        let mut wrr = WeightedRoundRobin::<4>::new();
        wrr.add(BackendEntry::new(1, 5));
        wrr.add(BackendEntry::new(2, 3));
        wrr.add(BackendEntry::new(3, 2));

        let mut counts = [0u32; 4];
        for _ in 0..100 {
            let id = wrr.select().unwrap();
            counts[id as usize] += 1;
        }
        // weight比 5:3:2
        assert_eq!(counts[1], 50);
        assert_eq!(counts[2], 30);
        assert_eq!(counts[3], 20);
    }

    #[test]
    fn wrr_unhealthy_skip() {
        let mut wrr = WeightedRoundRobin::<4>::new();
        wrr.add(BackendEntry::new(1, 1));
        wrr.add(BackendEntry::new(2, 1));
        wrr.set_healthy(2, false);

        for _ in 0..10 {
            assert_eq!(wrr.select(), Some(1));
        }
    }

    #[test]
    fn wrr_all_unhealthy() {
        let mut wrr = WeightedRoundRobin::<4>::new();
        wrr.add(BackendEntry::new(1, 1));
        wrr.set_healthy(1, false);
        assert_eq!(wrr.select(), None);
    }

    #[test]
    fn wrr_empty() {
        let mut wrr = WeightedRoundRobin::<4>::new();
        assert!(wrr.is_empty());
        assert_eq!(wrr.select(), None);
    }

    #[test]
    fn wrr_capacity_limit() {
        let mut wrr = WeightedRoundRobin::<2>::new();
        assert!(wrr.add(BackendEntry::new(1, 1)));
        assert!(wrr.add(BackendEntry::new(2, 1)));
        assert!(!wrr.add(BackendEntry::new(3, 1)));
        assert_eq!(wrr.len(), 2);
    }

    // --- Least Connections ---

    #[test]
    fn lc_basic() {
        let mut lc = LeastConnections::<4>::new();
        lc.add(BackendEntry::new(1, 1));
        lc.add(BackendEntry::new(2, 1));

        // 両方0接続 → id=1（先頭）
        assert_eq!(lc.select(), Some(1));

        // id=1に接続追加 → id=2が選ばれる
        lc.connect(1);
        assert_eq!(lc.select(), Some(2));
    }

    #[test]
    fn lc_weight_tiebreak() {
        let mut lc = LeastConnections::<4>::new();
        lc.add(BackendEntry::new(1, 1));
        lc.add(BackendEntry::new(2, 5)); // 重い

        // 同接続数 → 重みの大きいid=2を優先
        assert_eq!(lc.select(), Some(2));
    }

    #[test]
    fn lc_disconnect() {
        let mut lc = LeastConnections::<4>::new();
        lc.add(BackendEntry::new(1, 1));
        lc.add(BackendEntry::new(2, 1));

        lc.connect(1);
        lc.connect(1);
        lc.connect(2);
        // id=1: 2, id=2: 1 → id=2
        assert_eq!(lc.select(), Some(2));

        lc.disconnect(1);
        lc.disconnect(1);
        // id=1: 0, id=2: 1 → id=1
        assert_eq!(lc.select(), Some(1));
    }

    #[test]
    fn lc_unhealthy() {
        let mut lc = LeastConnections::<4>::new();
        lc.add(BackendEntry::new(1, 1));
        lc.add(BackendEntry::new(2, 1));
        lc.set_healthy(1, false);

        assert_eq!(lc.select(), Some(2));
    }

    #[test]
    fn lc_empty() {
        let lc = LeastConnections::<4>::new();
        assert!(lc.is_empty());
        assert_eq!(lc.select(), None);
    }

    #[test]
    fn lc_saturating_disconnect() {
        let mut lc = LeastConnections::<4>::new();
        lc.add(BackendEntry::new(1, 1));
        // 0からdisconnectしてもアンダーフローしない
        lc.disconnect(1);
        assert_eq!(lc.select(), Some(1));
    }

    // --- Consistent Hash ---

    #[test]
    fn ch_sticky() {
        let mut ch = ConsistentHash::<8>::new();
        ch.add(BackendEntry::new(1, 1));
        ch.add(BackendEntry::new(2, 1));
        ch.add(BackendEntry::new(3, 1));

        let client_hash = 0xDEAD_BEEF_CAFE_1234;
        let first = ch.select(client_hash).unwrap();

        // 同じハッシュなら常に同じバックエンド
        for _ in 0..100 {
            assert_eq!(ch.select(client_hash), Some(first));
        }
    }

    #[test]
    fn ch_distribution() {
        let mut ch = ConsistentHash::<8>::new();
        for i in 1..=4 {
            ch.add(BackendEntry::new(i, 1));
        }

        let mut hit = [false; 5];
        // 十分な数のクライアントで全バックエンドに分散
        for i in 0..1000u64 {
            let id = ch.select(i.wrapping_mul(0x517c_c1b7_2722_0a95)).unwrap();
            hit[id as usize] = true;
        }
        for h in &hit[1..=4] {
            assert!(h, "全バックエンドに少なくとも1回は分散");
        }
    }

    #[test]
    fn ch_unhealthy_failover() {
        let mut ch = ConsistentHash::<8>::new();
        ch.add(BackendEntry::new(1, 1));
        ch.add(BackendEntry::new(2, 1));

        let client = 42;
        let original = ch.select(client).unwrap();

        // 選ばれたバックエンドをunhealthyに
        ch.set_healthy(original, false);
        let failover = ch.select(client).unwrap();
        assert_ne!(failover, original);
    }

    #[test]
    fn ch_empty() {
        let ch = ConsistentHash::<4>::new();
        assert!(ch.is_empty());
        assert_eq!(ch.select(123), None);
    }

    #[test]
    fn ch_all_unhealthy() {
        let mut ch = ConsistentHash::<4>::new();
        ch.add(BackendEntry::new(1, 1));
        ch.set_healthy(1, false);
        assert_eq!(ch.select(123), None);
        assert_eq!(ch.healthy_count(), 0);
    }

    // --- Jump Consistent Hash ---

    #[test]
    fn jch_single_bucket() {
        assert_eq!(jump_consistent_hash(12345, 1), 0);
    }

    #[test]
    fn jch_deterministic() {
        let a = jump_consistent_hash(0xABCD, 10);
        let b = jump_consistent_hash(0xABCD, 10);
        assert_eq!(a, b);
    }

    #[test]
    fn jch_range() {
        for key in 0..100u64 {
            let bucket = jump_consistent_hash(key, 8);
            assert!(bucket < 8);
        }
    }
}

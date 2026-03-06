//! バックエンドヘルスチェック
//!
//! 成功率ベースのヘルスチェッカー。
//! スライディングウィンドウで直近N回のプローブ結果を追跡し、
//! 成功率が閾値を下回ったら自動的に unhealthy 判定。
//! `no_std` 互換、ヒープ不使用。

// ============================================================================
// ヘルスチェック設定
// ============================================================================

/// ヘルスチェック設定。
#[derive(Debug, Clone, Copy)]
pub struct HealthConfig {
    /// 健全判定の成功率閾値 (0.0〜1.0)。
    pub healthy_threshold: f32,
    /// unhealthy → healthy 復帰に必要な連続成功数。
    pub recovery_count: u32,
    /// ヘルスチェック間隔（ナノ秒）。
    pub interval_ns: u64,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            healthy_threshold: 0.7,
            recovery_count: 3,
            interval_ns: 5_000_000_000, // 5秒
        }
    }
}

// ============================================================================
// バックエンドヘルスチェッカー
// ============================================================================

/// 1バックエンドのヘルス状態。
///
/// スライディングウィンドウ（リングバッファ）で直近 `WINDOW` 回の結果を記録。
pub struct HealthChecker<const WINDOW: usize> {
    /// プローブ結果リングバッファ（true=成功, false=失敗）。
    results: [bool; WINDOW],
    /// 次の書き込み位置。
    write_pos: usize,
    /// 記録済みプローブ数（最大WINDOW）。
    recorded: usize,
    /// 成功カウント（ウィンドウ内）。
    success_count: u32,
    /// 現在の連続成功数（recovery判定用）。
    consecutive_successes: u32,
    /// 健全状態。
    healthy: bool,
    /// 設定。
    config: HealthConfig,
    /// 最後のプローブ時刻（ns）。
    last_probe_ns: u64,
}

impl<const WINDOW: usize> HealthChecker<WINDOW> {
    /// 新しいヘルスチェッカーを作成（初期状態: healthy）。
    #[must_use]
    pub const fn new(config: HealthConfig) -> Self {
        Self {
            results: [false; WINDOW],
            write_pos: 0,
            recorded: 0,
            success_count: 0,
            consecutive_successes: 0,
            healthy: true,
            config,
            last_probe_ns: 0,
        }
    }

    /// プローブ結果を記録。
    pub fn record(&mut self, success: bool, now_ns: u64) {
        self.last_probe_ns = now_ns;

        // リングバッファから古い結果を削除
        if self.recorded >= WINDOW {
            let old = self.results[self.write_pos];
            if old {
                self.success_count = self.success_count.saturating_sub(1);
            }
        }

        // 新しい結果を記録
        self.results[self.write_pos] = success;
        self.write_pos = (self.write_pos + 1) % WINDOW;
        if self.recorded < WINDOW {
            self.recorded += 1;
        }

        if success {
            self.success_count += 1;
            self.consecutive_successes += 1;
        } else {
            self.consecutive_successes = 0;
        }

        // 健全性判定
        self.evaluate();
    }

    /// 健全性を評価・更新。
    fn evaluate(&mut self) {
        if self.recorded == 0 {
            return;
        }

        let rate = self.success_count as f32 / self.recorded as f32;

        if self.healthy {
            // 健全 → 成功率が閾値を下回ったら unhealthy
            if rate < self.config.healthy_threshold {
                self.healthy = false;
            }
        } else {
            // 不健全 → 連続成功が recovery_count に達したら healthy
            if self.consecutive_successes >= self.config.recovery_count {
                self.healthy = true;
            }
        }
    }

    /// 健全か。
    #[inline]
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        self.healthy
    }

    /// 現在の成功率 (0.0〜1.0)。
    #[must_use]
    pub fn success_rate(&self) -> f32 {
        if self.recorded == 0 {
            return 1.0; // 未記録時は健全とみなす
        }
        self.success_count as f32 / self.recorded as f32
    }

    /// 次のプローブ実行可能時刻か。
    #[must_use]
    pub const fn should_probe(&self, now_ns: u64) -> bool {
        now_ns.saturating_sub(self.last_probe_ns) >= self.config.interval_ns
    }

    /// ウィンドウ内の記録数。
    #[inline]
    #[must_use]
    pub const fn recorded(&self) -> usize {
        self.recorded
    }

    /// 強制リセット。
    pub const fn reset(&mut self) {
        self.results = [false; WINDOW];
        self.write_pos = 0;
        self.recorded = 0;
        self.success_count = 0;
        self.consecutive_successes = 0;
        self.healthy = true;
        self.last_probe_ns = 0;
    }
}

// ============================================================================
// マルチバックエンドヘルスレジストリ
// ============================================================================

/// 複数バックエンドのヘルスチェックレジストリ。
pub struct HealthRegistry<const N: usize, const WINDOW: usize> {
    checkers: [(u32, HealthChecker<WINDOW>); N],
    count: usize,
    config: HealthConfig,
}

impl<const N: usize, const WINDOW: usize> HealthRegistry<N, WINDOW> {
    /// 新しいレジストリを作成。
    #[must_use]
    pub fn new(config: HealthConfig) -> Self {
        Self {
            checkers: core::array::from_fn(|_| (0, HealthChecker::new(config))),
            count: 0,
            config,
        }
    }

    /// バックエンドを登録。
    pub const fn register(&mut self, backend_id: u32) -> bool {
        if self.count >= N {
            return false;
        }
        self.checkers[self.count] = (backend_id, HealthChecker::new(self.config));
        self.count += 1;
        true
    }

    /// バックエンドのヘルスチェッカーを取得。
    #[must_use]
    pub fn get(&self, backend_id: u32) -> Option<&HealthChecker<WINDOW>> {
        self.checkers[..self.count]
            .iter()
            .find(|(id, _)| *id == backend_id)
            .map(|(_, hc)| hc)
    }

    /// バックエンドのヘルスチェッカーを可変取得。
    pub fn get_mut(&mut self, backend_id: u32) -> Option<&mut HealthChecker<WINDOW>> {
        self.checkers[..self.count]
            .iter_mut()
            .find(|(id, _)| *id == backend_id)
            .map(|(_, hc)| hc)
    }

    /// バックエンドが健全か。
    #[must_use]
    pub fn is_healthy(&self, backend_id: u32) -> bool {
        self.get(backend_id).is_some_and(HealthChecker::is_healthy)
    }

    /// 健全なバックエンドIDのリストを返す。
    #[must_use]
    pub fn healthy_backends(&self) -> ([u32; N], usize) {
        let mut ids = [0u32; N];
        let mut count = 0;
        for (id, hc) in &self.checkers[..self.count] {
            if hc.is_healthy() {
                ids[count] = *id;
                count += 1;
            }
        }
        (ids, count)
    }

    /// 登録数。
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
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {
    use super::*;

    fn test_config() -> HealthConfig {
        HealthConfig {
            healthy_threshold: 0.5,
            recovery_count: 2,
            interval_ns: 1000,
        }
    }

    // --- HealthChecker ---

    #[test]
    fn initial_healthy() {
        let hc = HealthChecker::<8>::new(test_config());
        assert!(hc.is_healthy());
        assert_eq!(hc.success_rate(), 1.0); // 未記録
        assert_eq!(hc.recorded(), 0);
    }

    #[test]
    fn all_success_stays_healthy() {
        let mut hc = HealthChecker::<8>::new(test_config());
        for i in 0..8u64 {
            hc.record(true, i * 100);
        }
        assert!(hc.is_healthy());
        assert_eq!(hc.success_rate(), 1.0);
    }

    #[test]
    fn failure_below_threshold_unhealthy() {
        let mut hc = HealthChecker::<4>::new(test_config());
        // threshold=0.5, 4回中1成功 → 25% < 50% → unhealthy
        hc.record(true, 100);
        hc.record(false, 200);
        hc.record(false, 300);
        hc.record(false, 400);

        assert!(!hc.is_healthy());
    }

    #[test]
    fn recovery_needs_consecutive_successes() {
        let mut hc = HealthChecker::<4>::new(test_config());
        // まず unhealthy にする
        hc.record(false, 100);
        hc.record(false, 200);
        hc.record(false, 300);
        hc.record(false, 400);
        assert!(!hc.is_healthy());

        // 1回成功では復帰しない（recovery_count=2）
        hc.record(true, 500);
        assert!(!hc.is_healthy());

        // 2連続成功で復帰
        hc.record(true, 600);
        assert!(hc.is_healthy());
    }

    #[test]
    fn recovery_reset_on_failure() {
        let mut hc = HealthChecker::<4>::new(test_config());
        hc.record(false, 100);
        hc.record(false, 200);
        hc.record(false, 300);
        hc.record(false, 400);
        assert!(!hc.is_healthy());

        hc.record(true, 500); // 連続1
        hc.record(false, 600); // リセット
        hc.record(true, 700); // 連続1
        assert!(!hc.is_healthy());
    }

    #[test]
    fn sliding_window_evicts_old() {
        let mut hc = HealthChecker::<4>::new(test_config());
        // 4回失敗 → unhealthy
        hc.record(false, 100);
        hc.record(false, 200);
        hc.record(false, 300);
        hc.record(false, 400);
        assert!(!hc.is_healthy());

        // 新しい成功が古い失敗を押し出す
        hc.record(true, 500);
        hc.record(true, 600); // recovery_count=2達成
        assert!(hc.is_healthy());

        // ウィンドウ: [false, false, true, true] → 50% = threshold → まだhealthy
        assert!((hc.success_rate() - 0.5).abs() < 0.01);
    }

    #[test]
    fn should_probe_interval() {
        let hc = HealthChecker::<4>::new(test_config());
        // last_probe_ns=0, interval=1000
        assert!(!hc.should_probe(500)); // 500 < 1000 → false
        assert!(hc.should_probe(1000)); // 1000 >= 1000 → true
        assert!(hc.should_probe(2000)); // 2000 >= 1000 → true
    }

    #[test]
    fn should_probe_after_record() {
        let mut hc = HealthChecker::<4>::new(test_config());
        hc.record(true, 5000);
        assert!(!hc.should_probe(5500)); // 500ns < 1000ns interval
        assert!(hc.should_probe(6000)); // 1000ns >= interval
    }

    #[test]
    fn reset_clears_state() {
        let mut hc = HealthChecker::<4>::new(test_config());
        hc.record(false, 100);
        hc.record(false, 200);
        hc.record(false, 300);
        hc.record(false, 400);
        assert!(!hc.is_healthy());

        hc.reset();
        assert!(hc.is_healthy());
        assert_eq!(hc.recorded(), 0);
        assert_eq!(hc.success_rate(), 1.0);
    }

    #[test]
    fn config_default() {
        let cfg = HealthConfig::default();
        assert_eq!(cfg.healthy_threshold, 0.7);
        assert_eq!(cfg.recovery_count, 3);
        assert_eq!(cfg.interval_ns, 5_000_000_000);
    }

    // --- HealthRegistry ---

    #[test]
    fn registry_basic() {
        let mut reg = HealthRegistry::<4, 8>::new(test_config());
        assert!(reg.register(1));
        assert!(reg.register(2));
        assert_eq!(reg.len(), 2);

        assert!(reg.is_healthy(1));
        assert!(reg.is_healthy(2));
        assert!(!reg.is_healthy(99)); // 未登録
    }

    #[test]
    fn registry_healthy_backends() {
        let mut reg = HealthRegistry::<4, 4>::new(test_config());
        reg.register(1);
        reg.register(2);
        reg.register(3);

        // id=2を unhealthy にする
        if let Some(hc) = reg.get_mut(2) {
            hc.record(false, 100);
            hc.record(false, 200);
            hc.record(false, 300);
            hc.record(false, 400);
        }

        let (ids, count) = reg.healthy_backends();
        assert_eq!(count, 2);
        assert_eq!(ids[0], 1);
        assert_eq!(ids[1], 3);
    }

    #[test]
    fn registry_capacity() {
        let mut reg = HealthRegistry::<2, 4>::new(test_config());
        assert!(reg.register(1));
        assert!(reg.register(2));
        assert!(!reg.register(3));
    }

    #[test]
    fn registry_empty() {
        let reg = HealthRegistry::<4, 4>::new(test_config());
        assert!(reg.is_empty());
        let (_, count) = reg.healthy_backends();
        assert_eq!(count, 0);
    }
}

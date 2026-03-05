//! サーキットブレーカーパターン
//!
//! バックエンド障害時の連鎖障害を防止。
//! Closed → Open → HalfOpen の3状態遷移。
//! `no_std` 互換、ヒープ不使用。

// ============================================================================
// 状態
// ============================================================================

/// サーキットブレーカーの状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    /// 正常動作中。リクエストを通す。
    Closed,
    /// 障害検出。リクエストを遮断。
    Open,
    /// 回復確認中。限定的にリクエストを通す。
    HalfOpen,
}

// ============================================================================
// 設定
// ============================================================================

/// サーキットブレーカーの設定。
#[derive(Debug, Clone, Copy)]
pub struct BreakerConfig {
    /// Closed→Open へ遷移する失敗率閾値 (0.0〜1.0)。
    pub failure_threshold: f32,
    /// 判定に必要な最小リクエスト数。
    pub min_requests: u32,
    /// Open 状態の持続時間（ナノ秒）。
    pub open_duration_ns: u64,
    /// HalfOpen 中に通すテストリクエスト数。
    pub half_open_max_requests: u32,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 0.5,
            min_requests: 10,
            open_duration_ns: 30_000_000_000, // 30秒
            half_open_max_requests: 3,
        }
    }
}

// ============================================================================
// サーキットブレーカー
// ============================================================================

/// サーキットブレーカー。
///
/// タイムスタンプベースで動作（外部クロック注入）。
#[derive(Debug)]
pub struct CircuitBreaker {
    config: BreakerConfig,
    state: BreakerState,
    /// ウィンドウ内の成功数。
    successes: u32,
    /// ウィンドウ内の失敗数。
    failures: u32,
    /// Open に遷移した時刻（ns）。
    opened_at_ns: u64,
    /// HalfOpen 中のテストリクエスト数。
    half_open_requests: u32,
    /// HalfOpen 中の成功数。
    half_open_successes: u32,
}

impl CircuitBreaker {
    /// 新しいサーキットブレーカーを作成。
    #[must_use]
    pub const fn new(config: BreakerConfig) -> Self {
        Self {
            config,
            state: BreakerState::Closed,
            successes: 0,
            failures: 0,
            opened_at_ns: 0,
            half_open_requests: 0,
            half_open_successes: 0,
        }
    }

    /// 現在の状態を取得。
    #[inline]
    #[must_use]
    pub const fn state(&self) -> BreakerState {
        self.state
    }

    /// リクエスト許可判定。
    ///
    /// `now_ns` は現在のタイムスタンプ（ナノ秒）。
    /// `true` = リクエスト許可、 `false` = 遮断。
    #[must_use]
    pub fn allow(&mut self, now_ns: u64) -> bool {
        match self.state {
            BreakerState::Closed => true,
            BreakerState::Open => {
                // Open 期間経過 → HalfOpen へ遷移
                if now_ns.saturating_sub(self.opened_at_ns) >= self.config.open_duration_ns {
                    self.state = BreakerState::HalfOpen;
                    self.half_open_requests = 0;
                    self.half_open_successes = 0;
                    true
                } else {
                    false
                }
            }
            BreakerState::HalfOpen => {
                self.half_open_requests < self.config.half_open_max_requests
            }
        }
    }

    /// 成功を記録。
    pub fn record_success(&mut self) {
        match self.state {
            BreakerState::Closed => {
                self.successes += 1;
            }
            BreakerState::HalfOpen => {
                self.half_open_requests += 1;
                self.half_open_successes += 1;
                // テストリクエストがすべて成功 → Closed へ
                if self.half_open_successes >= self.config.half_open_max_requests {
                    self.reset();
                }
            }
            BreakerState::Open => {}
        }
    }

    /// 失敗を記録。
    pub fn record_failure(&mut self, now_ns: u64) {
        match self.state {
            BreakerState::Closed => {
                self.failures += 1;
                self.check_threshold(now_ns);
            }
            BreakerState::HalfOpen => {
                // HalfOpen中に失敗 → 即Open
                self.half_open_requests += 1;
                self.trip(now_ns);
            }
            BreakerState::Open => {}
        }
    }

    /// 失敗率を確認し、閾値超過なら Open へ遷移。
    fn check_threshold(&mut self, now_ns: u64) {
        let total = self.successes + self.failures;
        if total < self.config.min_requests {
            return;
        }
        let failure_rate = self.failures as f32 / total as f32;
        if failure_rate >= self.config.failure_threshold {
            self.trip(now_ns);
        }
    }

    /// Open 状態へ遷移。
    fn trip(&mut self, now_ns: u64) {
        self.state = BreakerState::Open;
        self.opened_at_ns = now_ns;
    }

    /// Closed 状態にリセット。
    pub fn reset(&mut self) {
        self.state = BreakerState::Closed;
        self.successes = 0;
        self.failures = 0;
        self.half_open_requests = 0;
        self.half_open_successes = 0;
    }

    /// 成功数。
    #[inline]
    #[must_use]
    pub const fn successes(&self) -> u32 {
        self.successes
    }

    /// 失敗数。
    #[inline]
    #[must_use]
    pub const fn failures(&self) -> u32 {
        self.failures
    }

    /// 現在の失敗率 (0.0〜1.0)。リクエスト0なら0.0。
    #[must_use]
    pub fn failure_rate(&self) -> f32 {
        let total = self.successes + self.failures;
        if total == 0 {
            return 0.0;
        }
        self.failures as f32 / total as f32
    }
}

// ============================================================================
// マルチバックエンド管理
// ============================================================================

/// 複数バックエンドのサーキットブレーカー管理。
pub struct BreakerRegistry<const N: usize> {
    breakers: [(u32, CircuitBreaker); N],
    count: usize,
    config: BreakerConfig,
}

impl<const N: usize> BreakerRegistry<N> {
    /// 新しいレジストリを作成。
    #[must_use]
    pub fn new(config: BreakerConfig) -> Self {
        Self {
            breakers: core::array::from_fn(|_| (0, CircuitBreaker::new(config))),
            count: 0,
            config,
        }
    }

    /// バックエンドを登録。
    pub fn register(&mut self, backend_id: u32) -> bool {
        if self.count >= N {
            return false;
        }
        self.breakers[self.count] = (backend_id, CircuitBreaker::new(self.config));
        self.count += 1;
        true
    }

    /// バックエンドのブレーカーを取得。
    #[must_use]
    pub fn get(&self, backend_id: u32) -> Option<&CircuitBreaker> {
        self.breakers[..self.count]
            .iter()
            .find(|(id, _)| *id == backend_id)
            .map(|(_, cb)| cb)
    }

    /// バックエンドのブレーカーを可変取得。
    pub fn get_mut(&mut self, backend_id: u32) -> Option<&mut CircuitBreaker> {
        self.breakers[..self.count]
            .iter_mut()
            .find(|(id, _)| *id == backend_id)
            .map(|(_, cb)| cb)
    }

    /// リクエスト許可判定。
    #[must_use]
    pub fn allow(&mut self, backend_id: u32, now_ns: u64) -> bool {
        self.get_mut(backend_id)
            .is_some_and(|cb| cb.allow(now_ns))
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

    fn default_breaker() -> CircuitBreaker {
        CircuitBreaker::new(BreakerConfig {
            failure_threshold: 0.5,
            min_requests: 4,
            open_duration_ns: 10_000,
            half_open_max_requests: 2,
        })
    }

    #[test]
    fn initial_state_closed() {
        let cb = default_breaker();
        assert_eq!(cb.state(), BreakerState::Closed);
        assert_eq!(cb.successes(), 0);
        assert_eq!(cb.failures(), 0);
    }

    #[test]
    fn closed_allows_requests() {
        let mut cb = default_breaker();
        assert!(cb.allow(0));
        assert!(cb.allow(1000));
    }

    #[test]
    fn trip_on_threshold() {
        let mut cb = default_breaker();
        // 4リクエスト中3失敗 → 75% > 50% → Open
        cb.record_success();
        cb.record_failure(100);
        cb.record_failure(200);
        cb.record_failure(300);

        assert_eq!(cb.state(), BreakerState::Open);
    }

    #[test]
    fn below_min_requests_no_trip() {
        let mut cb = default_breaker();
        // min_requests=4 未満では tripping しない
        cb.record_failure(100);
        cb.record_failure(200);
        cb.record_failure(300);

        assert_eq!(cb.state(), BreakerState::Closed);
    }

    #[test]
    fn open_blocks_requests() {
        let mut cb = default_breaker();
        // trip
        for i in 0..4u64 {
            cb.record_failure(i * 100);
        }
        assert_eq!(cb.state(), BreakerState::Open);
        assert!(!cb.allow(500));
    }

    #[test]
    fn open_to_half_open_after_duration() {
        let mut cb = default_breaker();
        for i in 0..4u64 {
            cb.record_failure(i * 100);
        }
        // Open at t=300, duration=10000 → HalfOpen at t>=10300
        assert!(!cb.allow(5000));
        assert!(cb.allow(11000));
        assert_eq!(cb.state(), BreakerState::HalfOpen);
    }

    #[test]
    fn half_open_success_closes() {
        let mut cb = default_breaker();
        for i in 0..4u64 {
            cb.record_failure(i * 100);
        }
        // → HalfOpen
        let _ = cb.allow(20000);
        assert_eq!(cb.state(), BreakerState::HalfOpen);

        // half_open_max_requests=2、全成功 → Closed
        cb.record_success();
        assert_eq!(cb.state(), BreakerState::HalfOpen);
        cb.record_success();
        assert_eq!(cb.state(), BreakerState::Closed);
    }

    #[test]
    fn half_open_failure_reopens() {
        let mut cb = default_breaker();
        for i in 0..4u64 {
            cb.record_failure(i * 100);
        }
        let _ = cb.allow(20000); // → HalfOpen

        cb.record_failure(25000);
        assert_eq!(cb.state(), BreakerState::Open);
    }

    #[test]
    fn half_open_limits_requests() {
        let mut cb = default_breaker();
        for i in 0..4u64 {
            cb.record_failure(i * 100);
        }
        let _ = cb.allow(20000); // → HalfOpen

        // half_open_max_requests=2
        assert!(cb.allow(20001));
        assert!(cb.allow(20002));
        // 2リクエスト発行済み（allow内でカウントはしていないがrecord_*でカウント）
        // record_successを1回呼んでhalf_open_requests=1に
        cb.record_success(); // half_open_requests=1
        assert!(cb.allow(20003)); // half_open_requests < 2 → true
        cb.record_success(); // half_open_requests=2 → Closed
        assert_eq!(cb.state(), BreakerState::Closed);
    }

    #[test]
    fn reset_returns_to_closed() {
        let mut cb = default_breaker();
        for i in 0..4u64 {
            cb.record_failure(i * 100);
        }
        assert_eq!(cb.state(), BreakerState::Open);

        cb.reset();
        assert_eq!(cb.state(), BreakerState::Closed);
        assert_eq!(cb.successes(), 0);
        assert_eq!(cb.failures(), 0);
    }

    #[test]
    fn failure_rate_calculation() {
        let mut cb = default_breaker();
        assert_eq!(cb.failure_rate(), 0.0);

        cb.record_success();
        cb.record_success();
        cb.record_failure(100);

        // 1/3 ≈ 0.333
        let rate = cb.failure_rate();
        assert!((rate - 1.0 / 3.0).abs() < 0.01);
    }

    #[test]
    fn config_default() {
        let cfg = BreakerConfig::default();
        assert_eq!(cfg.failure_threshold, 0.5);
        assert_eq!(cfg.min_requests, 10);
        assert_eq!(cfg.open_duration_ns, 30_000_000_000);
        assert_eq!(cfg.half_open_max_requests, 3);
    }

    // --- Registry ---

    #[test]
    fn registry_basic() {
        let mut reg = BreakerRegistry::<4>::new(BreakerConfig::default());
        assert!(reg.register(1));
        assert!(reg.register(2));
        assert_eq!(reg.len(), 2);

        assert!(reg.allow(1, 0));
        assert!(reg.allow(2, 0));
        assert!(!reg.allow(99, 0)); // 未登録
    }

    #[test]
    fn registry_capacity() {
        let mut reg = BreakerRegistry::<2>::new(BreakerConfig::default());
        assert!(reg.register(1));
        assert!(reg.register(2));
        assert!(!reg.register(3));
    }

    #[test]
    fn registry_get() {
        let mut reg = BreakerRegistry::<4>::new(BreakerConfig::default());
        reg.register(42);

        let cb = reg.get(42).unwrap();
        assert_eq!(cb.state(), BreakerState::Closed);

        assert!(reg.get(99).is_none());
    }

    #[test]
    fn registry_empty() {
        let reg = BreakerRegistry::<4>::new(BreakerConfig::default());
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
    }
}

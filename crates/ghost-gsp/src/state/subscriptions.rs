//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//| ░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░      ▒ ░░▒░▒ ░░▒░  |
//| ▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░         ▒ ░░▒░▒░ ░  |
//|  ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░               ░  ░    |
//|  ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░                            |
//|       ░              ░                                                                                               |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: state/subscriptions.rs                                                                                         |
//|======================================================================================================================|

//! Subscription manager for real-time push notifications

use std::collections::{HashMap, HashSet};

use parking_lot::RwLock;

use ghost_gsp_proto::WalletId;

/// Subscription types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubscriptionType {
    /// Balance updates
    Balance,
    /// Payment notifications
    Payments,
    /// Lock state changes
    Locks,
    /// Chain reorganization notifications (L1 and L2)
    Reorgs,
    /// BIP-352 silent-payment candidate-transaction pushes
    SilentPayments,
}

impl SubscriptionType {
    /// Parse a subscription name, case-insensitively.
    ///
    /// Named `from_name` rather than `from_str`: the latter shadows
    /// `std::str::FromStr::from_str`, so a caller with the trait in scope could reach a
    /// different method than they meant. Implementing `FromStr` properly is not the answer
    /// either — it returns `Result`, and an unknown subscription name is an ordinary `None`
    /// here, not an error worth a type.
    pub fn from_name(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "balance" => Some(SubscriptionType::Balance),
            "payments" => Some(SubscriptionType::Payments),
            "locks" => Some(SubscriptionType::Locks),
            "reorgs" => Some(SubscriptionType::Reorgs),
            "silent_payments" | "silentpayments" | "silent-payments" => {
                Some(SubscriptionType::SilentPayments)
            }
            _ => None,
        }
    }

    /// Get string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            SubscriptionType::Balance => "balance",
            SubscriptionType::Payments => "payments",
            SubscriptionType::Locks => "locks",
            SubscriptionType::Reorgs => "reorgs",
            SubscriptionType::SilentPayments => "silent_payments",
        }
    }
}

/// M-13 FIX: Maximum lock subscriptions per wallet (global, not per-connection)
/// This prevents a wallet from subscribing to excessive locks even across connections.
const MAX_LOCK_SUBSCRIPTIONS_PER_WALLET: usize = 100;

/// Manager for WebSocket subscriptions
pub struct SubscriptionManager {
    /// wallet_id -> set of subscription types
    subscriptions: RwLock<HashMap<String, HashSet<SubscriptionType>>>,

    /// lock_id -> set of wallet_ids subscribed to that lock's state updates
    lock_state_subscriptions: RwLock<HashMap<String, HashSet<String>>>,

    /// M-13 FIX: wallet_id -> set of lock_ids this wallet is subscribed to (global tracking)
    /// This enables enforcement of per-wallet lock subscription limits across all connections.
    wallet_lock_subscriptions: RwLock<HashMap<String, HashSet<String>>>,
}

impl SubscriptionManager {
    /// Create a new subscription manager
    pub fn new() -> Self {
        Self {
            subscriptions: RwLock::new(HashMap::new()),
            lock_state_subscriptions: RwLock::new(HashMap::new()),
            wallet_lock_subscriptions: RwLock::new(HashMap::new()),
        }
    }

    /// Add a subscription for a wallet
    pub fn subscribe(&self, wallet_id: &WalletId, subscription: &str) {
        if let Some(sub_type) = SubscriptionType::from_name(subscription) {
            let mut subs = self.subscriptions.write();
            subs.entry(wallet_id.to_string())
                .or_default()
                .insert(sub_type);
        }
    }

    /// Remove a subscription for a wallet
    pub fn unsubscribe(&self, wallet_id: &WalletId, subscription: &str) {
        if let Some(sub_type) = SubscriptionType::from_name(subscription) {
            let mut subs = self.subscriptions.write();
            if let Some(wallet_subs) = subs.get_mut(&wallet_id.to_string()) {
                wallet_subs.remove(&sub_type);
                if wallet_subs.is_empty() {
                    subs.remove(&wallet_id.to_string());
                }
            }
        }
    }

    /// Remove all subscriptions for a wallet
    pub fn unsubscribe_all(&self, wallet_id: &WalletId) {
        let mut subs = self.subscriptions.write();
        subs.remove(&wallet_id.to_string());
    }

    /// Check if a wallet is subscribed to a type
    pub fn is_subscribed(&self, wallet_id: &WalletId, sub_type: SubscriptionType) -> bool {
        let subs = self.subscriptions.read();
        subs.get(&wallet_id.to_string())
            .map(|s| s.contains(&sub_type))
            .unwrap_or(false)
    }

    /// Get all wallet IDs subscribed to a type
    pub fn get_subscribers(&self, sub_type: SubscriptionType) -> Vec<WalletId> {
        let subs = self.subscriptions.read();
        subs.iter()
            .filter(|(_, types)| types.contains(&sub_type))
            .map(|(id, _)| WalletId::from(id.clone()))
            .collect()
    }

    /// Get subscription count
    pub fn subscription_count(&self) -> usize {
        let subs = self.subscriptions.read();
        subs.values().map(|s| s.len()).sum()
    }

    /// Get unique wallet count with subscriptions
    pub fn wallet_count(&self) -> usize {
        self.subscriptions.read().len()
    }

    // =========================================================================
    // Lock State Subscriptions (for instant payments)
    // =========================================================================

    /// M-13 FIX: Check if wallet can subscribe to another lock (under global limit)
    ///
    /// Returns true if the wallet has room for more lock subscriptions.
    /// This is checked globally across all connections for this wallet.
    pub fn can_subscribe_lock(&self, wallet_id: &WalletId) -> bool {
        let wallet_subs = self.wallet_lock_subscriptions.read();
        wallet_subs
            .get(&wallet_id.to_string())
            .map(|locks| locks.len() < MAX_LOCK_SUBSCRIPTIONS_PER_WALLET)
            .unwrap_or(true)
    }

    /// M-13 FIX: Get the current lock subscription count for a wallet
    pub fn wallet_lock_subscription_count(&self, wallet_id: &WalletId) -> usize {
        let wallet_subs = self.wallet_lock_subscriptions.read();
        wallet_subs
            .get(&wallet_id.to_string())
            .map(|locks| locks.len())
            .unwrap_or(0)
    }

    /// Subscribe a wallet to lock state updates for a specific lock
    ///
    /// M-13 FIX: Returns Ok(true) if subscribed, Ok(false) if already subscribed,
    /// Err if the wallet has reached the global subscription limit.
    pub fn subscribe_lock_state(
        &self,
        wallet_id: &WalletId,
        lock_id: &str,
    ) -> Result<bool, &'static str> {
        let wallet_str = wallet_id.to_string();
        let lock_str = lock_id.to_string();

        // M-13 FIX: Check global per-wallet limit first
        {
            let wallet_subs = self.wallet_lock_subscriptions.read();
            if let Some(locks) = wallet_subs.get(&wallet_str) {
                // Already subscribed to this lock - no-op, return success
                if locks.contains(&lock_str) {
                    return Ok(false);
                }
                // Check limit
                if locks.len() >= MAX_LOCK_SUBSCRIPTIONS_PER_WALLET {
                    return Err("M-13: Maximum lock subscriptions per wallet exceeded");
                }
            }
        }

        // Add to lock -> wallets mapping
        {
            let mut subs = self.lock_state_subscriptions.write();
            subs.entry(lock_str.clone())
                .or_default()
                .insert(wallet_str.clone());
        }

        // M-13 FIX: Add to wallet -> locks mapping (global tracking)
        {
            let mut wallet_subs = self.wallet_lock_subscriptions.write();
            wallet_subs.entry(wallet_str).or_default().insert(lock_str);
        }

        Ok(true)
    }

    /// Unsubscribe a wallet from lock state updates for a specific lock
    ///
    /// M-13 FIX: Also removes from global wallet tracking
    pub fn unsubscribe_lock_state(&self, wallet_id: &WalletId, lock_id: &str) {
        let wallet_str = wallet_id.to_string();
        let lock_str = lock_id.to_string();

        // Remove from lock -> wallets mapping
        {
            let mut subs = self.lock_state_subscriptions.write();
            if let Some(lock_subs) = subs.get_mut(&lock_str) {
                lock_subs.remove(&wallet_str);
                if lock_subs.is_empty() {
                    subs.remove(&lock_str);
                }
            }
        }

        // M-13 FIX: Remove from wallet -> locks mapping
        {
            let mut wallet_subs = self.wallet_lock_subscriptions.write();
            if let Some(locks) = wallet_subs.get_mut(&wallet_str) {
                locks.remove(&lock_str);
                if locks.is_empty() {
                    wallet_subs.remove(&wallet_str);
                }
            }
        }
    }

    /// Unsubscribe a wallet from all lock state subscriptions
    ///
    /// M-13 FIX: Also clears global wallet tracking
    pub fn unsubscribe_all_lock_states(&self, wallet_id: &WalletId) {
        let wallet_str = wallet_id.to_string();

        // Remove from all lock -> wallets mappings
        {
            let mut subs = self.lock_state_subscriptions.write();

            // Remove wallet from all lock subscriptions
            let empty_locks: Vec<String> = subs
                .iter_mut()
                .filter_map(|(lock_id, wallets)| {
                    wallets.remove(&wallet_str);
                    if wallets.is_empty() {
                        Some(lock_id.clone())
                    } else {
                        None
                    }
                })
                .collect();

            // Clean up empty lock entries
            for lock_id in empty_locks {
                subs.remove(&lock_id);
            }
        }

        // M-13 FIX: Clear wallet -> locks mapping entirely
        {
            let mut wallet_subs = self.wallet_lock_subscriptions.write();
            wallet_subs.remove(&wallet_str);
        }
    }

    /// Get all wallet IDs subscribed to a specific lock's state updates
    pub fn get_lock_state_subscribers(&self, lock_id: &str) -> Vec<WalletId> {
        let subs = self.lock_state_subscriptions.read();
        subs.get(lock_id)
            .map(|wallets| {
                wallets
                    .iter()
                    .map(|id| WalletId::from(id.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Check if a wallet is subscribed to a lock's state updates
    pub fn is_subscribed_lock_state(&self, wallet_id: &WalletId, lock_id: &str) -> bool {
        let subs = self.lock_state_subscriptions.read();
        subs.get(lock_id)
            .map(|wallets| wallets.contains(&wallet_id.to_string()))
            .unwrap_or(false)
    }

    /// Get count of lock state subscriptions
    pub fn lock_state_subscription_count(&self) -> usize {
        let subs = self.lock_state_subscriptions.read();
        subs.values().map(|s| s.len()).sum()
    }

    // =========================================================================
    // Reorg Subscriptions
    // =========================================================================

    /// Subscribe a wallet to chain reorganization notifications
    pub fn subscribe_reorgs(&self, wallet_id: &WalletId) {
        let mut subs = self.subscriptions.write();
        subs.entry(wallet_id.to_string())
            .or_default()
            .insert(SubscriptionType::Reorgs);
    }

    /// Unsubscribe a wallet from chain reorganization notifications
    pub fn unsubscribe_reorgs(&self, wallet_id: &WalletId) {
        let mut subs = self.subscriptions.write();
        if let Some(wallet_subs) = subs.get_mut(&wallet_id.to_string()) {
            wallet_subs.remove(&SubscriptionType::Reorgs);
            if wallet_subs.is_empty() {
                subs.remove(&wallet_id.to_string());
            }
        }
    }

    /// Get all wallet IDs subscribed to reorg notifications
    pub fn get_reorg_subscribers(&self) -> Vec<WalletId> {
        self.get_subscribers(SubscriptionType::Reorgs)
    }

    /// Check if a wallet is subscribed to reorg notifications
    pub fn is_subscribed_reorgs(&self, wallet_id: &WalletId) -> bool {
        self.is_subscribed(wallet_id, SubscriptionType::Reorgs)
    }
}

impl Default for SubscriptionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::bool_assert_comparison)]
mod tests {
    use super::*;

    #[test]
    fn test_subscribe_unsubscribe() {
        let manager = SubscriptionManager::new();
        let wallet_id = WalletId::from("test_wallet".to_string());

        // Initially not subscribed
        assert!(!manager.is_subscribed(&wallet_id, SubscriptionType::Balance));

        // Subscribe
        manager.subscribe(&wallet_id, "balance");
        assert!(manager.is_subscribed(&wallet_id, SubscriptionType::Balance));

        // Unsubscribe
        manager.unsubscribe(&wallet_id, "balance");
        assert!(!manager.is_subscribed(&wallet_id, SubscriptionType::Balance));
    }

    #[test]
    fn test_multiple_subscriptions() {
        let manager = SubscriptionManager::new();
        let wallet_id = WalletId::from("test_wallet".to_string());

        manager.subscribe(&wallet_id, "balance");
        manager.subscribe(&wallet_id, "payments");
        manager.subscribe(&wallet_id, "locks");

        assert!(manager.is_subscribed(&wallet_id, SubscriptionType::Balance));
        assert!(manager.is_subscribed(&wallet_id, SubscriptionType::Payments));
        assert!(manager.is_subscribed(&wallet_id, SubscriptionType::Locks));

        assert_eq!(manager.subscription_count(), 3);
        assert_eq!(manager.wallet_count(), 1);
    }

    #[test]
    fn test_unsubscribe_all() {
        let manager = SubscriptionManager::new();
        let wallet_id = WalletId::from("test_wallet".to_string());

        manager.subscribe(&wallet_id, "balance");
        manager.subscribe(&wallet_id, "payments");

        manager.unsubscribe_all(&wallet_id);

        assert!(!manager.is_subscribed(&wallet_id, SubscriptionType::Balance));
        assert!(!manager.is_subscribed(&wallet_id, SubscriptionType::Payments));
        assert_eq!(manager.wallet_count(), 0);
    }

    #[test]
    fn test_get_subscribers() {
        let manager = SubscriptionManager::new();
        let wallet1 = WalletId::from("wallet1".to_string());
        let wallet2 = WalletId::from("wallet2".to_string());

        manager.subscribe(&wallet1, "balance");
        manager.subscribe(&wallet2, "balance");
        manager.subscribe(&wallet1, "payments");

        let balance_subs = manager.get_subscribers(SubscriptionType::Balance);
        assert_eq!(balance_subs.len(), 2);

        let payment_subs = manager.get_subscribers(SubscriptionType::Payments);
        assert_eq!(payment_subs.len(), 1);
    }

    #[test]
    fn test_invalid_subscription_type() {
        let manager = SubscriptionManager::new();
        let wallet_id = WalletId::from("test_wallet".to_string());

        // Invalid type should be ignored
        manager.subscribe(&wallet_id, "invalid");
        assert_eq!(manager.wallet_count(), 0);
    }

    // M-13 FIX: Global lock subscription tracking tests
    #[test]
    fn test_m13_lock_subscription_basic() {
        let manager = SubscriptionManager::new();
        let wallet_id = WalletId::from("test_wallet_12345678901234".to_string());

        // Initially no subscriptions
        assert_eq!(manager.wallet_lock_subscription_count(&wallet_id), 0);
        assert!(manager.can_subscribe_lock(&wallet_id));

        // Subscribe to a lock
        let result = manager.subscribe_lock_state(&wallet_id, "lock1");
        assert!(result.is_ok());
        assert_eq!(manager.wallet_lock_subscription_count(&wallet_id), 1);

        // Subscribe again should be idempotent
        let result = manager.subscribe_lock_state(&wallet_id, "lock1");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), false); // Already subscribed
        assert_eq!(manager.wallet_lock_subscription_count(&wallet_id), 1);

        // Subscribe to another lock
        let result = manager.subscribe_lock_state(&wallet_id, "lock2");
        assert!(result.is_ok());
        assert_eq!(manager.wallet_lock_subscription_count(&wallet_id), 2);

        // Unsubscribe from one
        manager.unsubscribe_lock_state(&wallet_id, "lock1");
        assert_eq!(manager.wallet_lock_subscription_count(&wallet_id), 1);

        // Unsubscribe from all
        manager.unsubscribe_all_lock_states(&wallet_id);
        assert_eq!(manager.wallet_lock_subscription_count(&wallet_id), 0);
    }

    #[test]
    fn test_m13_lock_subscription_limit() {
        let manager = SubscriptionManager::new();
        let wallet_id = WalletId::from("test_wallet_12345678901234".to_string());

        // Subscribe up to the limit
        for i in 0..MAX_LOCK_SUBSCRIPTIONS_PER_WALLET {
            let lock_id = format!("lock_{}", i);
            let result = manager.subscribe_lock_state(&wallet_id, &lock_id);
            assert!(result.is_ok(), "M-13: Should allow subscription {}", i);
        }

        assert_eq!(
            manager.wallet_lock_subscription_count(&wallet_id),
            MAX_LOCK_SUBSCRIPTIONS_PER_WALLET
        );
        assert!(
            !manager.can_subscribe_lock(&wallet_id),
            "M-13: Should be at limit"
        );

        // One more should fail
        let result = manager.subscribe_lock_state(&wallet_id, "lock_overflow");
        assert!(
            result.is_err(),
            "M-13: Should reject subscription over limit"
        );

        // Unsubscribe one and try again
        manager.unsubscribe_lock_state(&wallet_id, "lock_0");
        assert!(
            manager.can_subscribe_lock(&wallet_id),
            "M-13: Should be under limit after unsubscribe"
        );

        let result = manager.subscribe_lock_state(&wallet_id, "lock_new");
        assert!(
            result.is_ok(),
            "M-13: Should allow subscription after unsubscribe"
        );
    }

    #[test]
    fn test_m13_lock_subscription_different_wallets() {
        let manager = SubscriptionManager::new();
        let wallet1 = WalletId::from("wallet1_1234567890123456".to_string());
        let wallet2 = WalletId::from("wallet2_1234567890123456".to_string());

        // Both wallets can subscribe to the same lock
        let result1 = manager.subscribe_lock_state(&wallet1, "lock1");
        let result2 = manager.subscribe_lock_state(&wallet2, "lock1");
        assert!(result1.is_ok());
        assert!(result2.is_ok());

        // Check subscribers
        let subscribers = manager.get_lock_state_subscribers("lock1");
        assert_eq!(subscribers.len(), 2);

        // Each wallet has independent count
        assert_eq!(manager.wallet_lock_subscription_count(&wallet1), 1);
        assert_eq!(manager.wallet_lock_subscription_count(&wallet2), 1);
    }
}

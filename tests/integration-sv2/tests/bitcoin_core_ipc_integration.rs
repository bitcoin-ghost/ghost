use integration_tests_sv2::{template_provider::DifficultyLevel, *};

// Pool propagates block via IPC
// Requires a real bitcoin-core/ghostd binary with IPC (`start_bitcoin_core`),
// which isn't available in CI — the Test job runs only `--lib --bins` + selected
// integration targets, but `cargo llvm-cov` (Coverage) runs `--tests` and would
// otherwise fail here. Run locally with `--ignored` against a built node.
#[ignore = "requires a bitcoin-core/ghostd IPC harness; run with --ignored"]
#[tokio::test]
async fn pool_propagates_block_with_bitcoin_core_ipc() {
    start_tracing();
    let bitcoin_core = start_bitcoin_core(DifficultyLevel::Low);
    let current_block_hash = bitcoin_core.get_best_block_hash().unwrap();
    let (pool, pool_addr, _) = start_pool(
        ipc_config(
            bitcoin_core.data_dir().clone(),
            bitcoin_core.is_signet(),
            None,
        ),
        &bitcoin_core,
        vec![],
        vec![],
        false,
    )
    .await;
    let (translator, tproxy_addr, _) =
        start_sv2_translator(&[pool_addr], false, vec![], vec![], None, false).await;
    let (_minerd_process, _minerd_addr) = start_minerd(tproxy_addr, None, None, false).await;
    let timeout = tokio::time::Duration::from_secs(60);
    let poll_interval = tokio::time::Duration::from_secs(2);
    let start_time = tokio::time::Instant::now();
    loop {
        tokio::time::sleep(poll_interval).await;
        let new_block_hash = bitcoin_core.get_best_block_hash().unwrap();
        if new_block_hash != current_block_hash {
            shutdown_all!(pool, translator);
            return;
        }
        if start_time.elapsed() > timeout {
            panic!(
                "Pool with BitcoinCoreIpc should have propagated a new block within {} seconds",
                timeout.as_secs()
            );
        }
    }
}

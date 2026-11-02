#!/bin/bash
# ─────────────────────────────────────────────────────────────────────
# soak-report.sh — Post-soak analysis and report generator
#
# Reads the soak log directory produced by soak-test.sh and generates
# a structured report with pass/fail verdict.
#
# Usage:
#   ./soak-report.sh <log-directory>
#   ./soak-report.sh soak-logs/20260303-140000
# ─────────────────────────────────────────────────────────────────────
set -uo pipefail

# ── Input ────────────────────────────────────────────────────────────

LOG_DIR="${1:-}"
if [[ -z "$LOG_DIR" || ! -d "$LOG_DIR" ]]; then
    echo "Usage: $0 <soak-log-directory>"
    echo "Example: $0 soak-logs/20260303-140000"
    exit 1
fi

MAIN_LOG="$LOG_DIR/soak.log"
EVENTS_LOG="$LOG_DIR/soak-events.jsonl"
METRICS_LOG="$LOG_DIR/soak-metrics.jsonl"
REPORT="$LOG_DIR/soak-report.txt"

if [[ ! -f "$MAIN_LOG" ]]; then
    echo "Error: $MAIN_LOG not found"
    exit 1
fi

# ── Helpers ──────────────────────────────────────────────────────────

count_events() {
    local type="$1" result="${2:-}" count
    if [[ -z "$result" ]]; then
        count=$(grep -c "\"type\":\"$type\"" "$EVENTS_LOG" 2>/dev/null) || true
    else
        count=$(grep "\"type\":\"$type\"" "$EVENTS_LOG" 2>/dev/null | grep -c "\"result\":\"$result\"") || true
    fi
    echo "${count:-0}"
}

# ── Generate Report ──────────────────────────────────────────────────

generate_report() {
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║         GHOST POOL — MAINNET READINESS SOAK REPORT          ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "Log directory: $LOG_DIR"
    echo ""

    # ── Duration ─────────────────────────────────────────────────
    echo "── Duration ──────────────────────────────────────────────────"
    local start_ts end_ts
    start_ts=$(sed 's/\x1b\[[0-9;]*m//g' "$MAIN_LOG" | grep -oP '^\[\K[0-9T:Z-]+' | head -1)
    end_ts=$(sed 's/\x1b\[[0-9;]*m//g' "$MAIN_LOG" | grep -oP '^\[\K[0-9T:Z-]+' | tail -1)
    echo "  Start: $start_ts"
    echo "  End:   $end_ts"

    if [[ -f "$EVENTS_LOG" ]]; then
        local total_iterations
        total_iterations=$(grep -c '"type":"health-check"' "$EVENTS_LOG" 2>/dev/null) || true
        echo "  Iterations completed: ${total_iterations:-0}"
    fi
    echo ""

    # ── Phase 0: Pre-flight ──────────────────────────────────────
    echo "── Phase 0: Pre-flight Checks ──────────────────────────────"
    if [[ -f "$EVENTS_LOG" ]]; then
        local p0_result
        p0_result=$(grep '"type":"phase0"' "$EVENTS_LOG" 2>/dev/null | grep -oP '"result":"[^"]*"' | head -1)
        if echo "$p0_result" | grep -q "failures=0"; then
            echo "  Result: PASS"
        else
            echo "  Result: FAIL ($p0_result)"
        fi
    else
        echo "  Result: No events log found"
    fi
    echo ""

    # ── Phase 1: Chaos Tests ─────────────────────────────────────
    echo "── Phase 1: Cluster Chaos Suite ─────────────────────────────"
    if [[ -f "$EVENTS_LOG" ]]; then
        local p1_result
        p1_result=$(grep '"type":"phase1"' "$EVENTS_LOG" 2>/dev/null | tail -1)
        if echo "$p1_result" | grep -q '"result":"passed'; then
            echo "  Result: PASS"
            echo "  Detail: $(echo "$p1_result" | grep -oP '"result":"[^"]*"')"
        elif echo "$p1_result" | grep -q "skipped"; then
            echo "  Result: SKIPPED (dry run)"
        else
            echo "  Result: FAIL"
            echo "  Detail: $(echo "$p1_result" | grep -oP '"result":"[^"]*"')"
        fi
    fi
    if [[ -f "$LOG_DIR/chaos-tests.log" ]]; then
        local chaos_summary
        chaos_summary=$(grep "^test result:" "$LOG_DIR/chaos-tests.log" 2>/dev/null | tail -1)
        if [[ -n "$chaos_summary" ]]; then
            local chaos_pass chaos_fail
            chaos_pass=$(echo "$chaos_summary" | grep -oP '\d+ passed' | grep -oP '\d+')
            chaos_fail=$(echo "$chaos_summary" | grep -oP '\d+ failed' | grep -oP '\d+')
            echo "  Tests passed: ${chaos_pass:-0}"
            echo "  Tests failed: ${chaos_fail:-0}"
        fi
    fi
    echo ""

    # ── Phase 2: Soak Loop ───────────────────────────────────────
    echo "── Phase 2: Sustained Soak ──────────────────────────────────"
    if [[ -f "$EVENTS_LOG" ]]; then
        local hc_pass hc_fail hc_total hc_rate
        hc_pass=$(count_events "health-check" "pass")
        hc_fail=$(count_events "health-check" "fail")
        hc_total=$((hc_pass + hc_fail))
        hc_rate=0
        if (( hc_total > 0 )); then
            hc_rate=$(( (hc_pass * 100) / hc_total ))
        fi
        echo "  Health checks: $hc_pass/$hc_total passed (${hc_rate}%)"

        local nc_pass nc_drift
        nc_pass=$(count_events "node-compare" "pass")
        nc_drift=$(count_events "node-compare" "drift")
        echo "  Node compare: $nc_pass passed, $nc_drift drift warnings"

        local dash_pass dash_partial
        dash_pass=$(count_events "dashboard-test" "pass")
        dash_partial=$(count_events "dashboard-test" "partial")
        echo "  Dashboard tests: $dash_pass passed, $dash_partial partial"

        local l2_pass l2_partial
        l2_pass=$(count_events "l2-test" "pass")
        l2_partial=$(count_events "l2-test" "partial")
        echo "  L2 tests: $l2_pass passed, $l2_partial partial"

        local l2_cons_ok l2_cons_mm
        l2_cons_ok=$(count_events "l2-consistency" "consistent")
        l2_cons_mm=$(count_events "l2-consistency" "mismatch")
        echo "  L2 consistency: $l2_cons_ok consistent, $l2_cons_mm mismatches"
    fi
    echo ""

    # ── Failure Injection ────────────────────────────────────────
    echo "── Failure Injection Results ────────────────────────────────"
    if [[ -f "$EVENTS_LOG" ]]; then
        local inject_events
        inject_events=$(grep '"type":"fault-inject"' "$EVENTS_LOG" 2>/dev/null || true)
        if [[ -n "$inject_events" ]]; then
            local labels
            labels=$(echo "$inject_events" | grep -oP '"detail":"[^"]*"' | sort -u)
            while IFS= read -r label_match; do
                local label
                label=$(echo "$label_match" | grep -oP '"detail":"\K[^"]*')
                local results
                results=$(echo "$inject_events" | grep "\"detail\":\"$label\"" | grep -oP '"result":"\K[^"]*')
                local final_result
                final_result=$(echo "$results" | tail -1)
                if [[ "$final_result" == "recovered" || "$final_result" == "healed" ]]; then
                    echo "  [PASS] $label -> $final_result"
                elif [[ "$final_result" == "start" ]]; then
                    echo "  [????] $label -> injection started, no recovery logged"
                else
                    echo "  [FAIL] $label -> $final_result"
                fi
            done <<< "$labels"
        else
            echo "  No fault injection events recorded"
        fi
    fi
    echo ""

    # ── Metrics Deltas ───────────────────────────────────────────
    echo "── Metrics Deltas (baseline vs final) ───────────────────────"
    local vm_num
    for vm_num in 1 2 3 4; do
        local baseline="$LOG_DIR/baseline-metrics-vm${vm_num}.txt"
        local final="$LOG_DIR/final-metrics-vm${vm_num}.txt"
        if [[ -f "$baseline" && -f "$final" ]]; then
            echo "  VM${vm_num}:"
            local metric
            for metric in "blocks_mined_total" "payout_errors_total" "consensus_rounds_total" "circuit_breaker_trips_total" "reorgs_detected_total"; do
                local base_val final_val
                base_val=$(grep -oP "${metric} \K[0-9.]+" "$baseline" 2>/dev/null | head -1)
                final_val=$(grep -oP "${metric} \K[0-9.]+" "$final" 2>/dev/null | head -1)
                if [[ -n "$base_val" || -n "$final_val" ]]; then
                    local delta=$((${final_val:-0} - ${base_val:-0}))
                    echo "    $metric: ${base_val:-0} -> ${final_val:-0} (delta: $delta)"
                fi
            done
        else
            echo "  VM${vm_num}: metrics files not found"
        fi
    done
    echo ""

    # ── DB Deltas ────────────────────────────────────────────────
    echo "── DB State Deltas (baseline vs final) ──────────────────────"
    for vm_num in 1 2 3 4; do
        local baseline="$LOG_DIR/baseline-db-vm${vm_num}.txt"
        local final="$LOG_DIR/final-db-vm${vm_num}.txt"
        if [[ -f "$baseline" && -f "$final" ]]; then
            echo "  VM${vm_num}:"
            echo "    Baseline: $(cat "$baseline" | tr '\n' ' ')"
            echo "    Final:    $(cat "$final" | tr '\n' ' ')"
        fi
    done
    echo ""

    # ── Phase 3: Post-soak ───────────────────────────────────────
    echo "── Phase 3: Post-soak Validation ────────────────────────────"
    if [[ -f "$EVENTS_LOG" ]]; then
        local p3_result
        p3_result=$(grep '"type":"phase3"' "$EVENTS_LOG" 2>/dev/null | tail -1)
        if echo "$p3_result" | grep -q "failures=0"; then
            echo "  Result: PASS"
        else
            echo "  Result: FAIL ($p3_result)"
        fi
    fi
    echo ""

    # ── Overall Verdict ──────────────────────────────────────────
    echo "══════════════════════════════════════════════════════════════"
    local verdict="PASS"
    local reasons=""

    if [[ -f "$EVENTS_LOG" ]]; then
        # Check phase 0
        if grep '"type":"phase0"' "$EVENTS_LOG" 2>/dev/null | grep -qv "failures=0"; then
            verdict="FAIL"
            reasons="${reasons}  - Phase 0 pre-flight failures\n"
        fi

        # Check phase 1
        if grep '"type":"phase1"' "$EVENTS_LOG" 2>/dev/null | grep -q '"result":"failed'; then
            verdict="FAIL"
            reasons="${reasons}  - Phase 1 chaos test failures\n"
        fi

        # Check health rate
        local hc_pass2 hc_fail2 hc_total2 hc_rate2
        hc_pass2=$(count_events "health-check" "pass")
        hc_fail2=$(count_events "health-check" "fail")
        hc_total2=$((hc_pass2 + hc_fail2))
        if (( hc_total2 > 0 )); then
            hc_rate2=$(( (hc_pass2 * 100) / hc_total2 ))
            if (( hc_rate2 < 95 )); then
                verdict="FAIL"
                reasons="${reasons}  - Health check rate ${hc_rate2}% (< 95%)\n"
            fi
        fi

        # Check payout errors in final metrics
        for vm_num in 1 2 3 4; do
            local final="$LOG_DIR/final-metrics-vm${vm_num}.txt"
            if [[ -f "$final" ]]; then
                local pe
                pe=$(grep -oP "payout_errors_total \K[0-9]+" "$final" 2>/dev/null | head -1)
                if [[ -n "$pe" && "$pe" -gt 0 ]]; then
                    verdict="FAIL"
                    reasons="${reasons}  - VM${vm_num}: $pe payout errors\n"
                fi
            fi
        done

        # Check fault injection results
        if grep '"type":"fault-inject"' "$EVENTS_LOG" 2>/dev/null | grep -qE '"result":"not-recovered|"result":"not-healed'; then
            verdict="FAIL"
            reasons="${reasons}  - Fault injection: unrecovered failure(s)\n"
        fi

        # Check phase 3
        if grep '"type":"phase3"' "$EVENTS_LOG" 2>/dev/null | grep -qv "failures=0"; then
            verdict="FAIL"
            reasons="${reasons}  - Phase 3 validation failures\n"
        fi
    else
        verdict="INCOMPLETE"
        reasons="  - No events log found\n"
    fi

    if [[ "$verdict" == "PASS" ]]; then
        echo "  OVERALL VERDICT: PASS"
    elif [[ "$verdict" == "INCOMPLETE" ]]; then
        echo "  OVERALL VERDICT: INCOMPLETE"
    else
        echo "  OVERALL VERDICT: FAIL"
        echo ""
        echo "  Failure reasons:"
        echo -e "$reasons"
    fi
    echo "══════════════════════════════════════════════════════════════"
}

generate_report | tee "$REPORT"

echo ""
echo "Report saved to: $REPORT"

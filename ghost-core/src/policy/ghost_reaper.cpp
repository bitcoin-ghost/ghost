// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/ghost_reaper.h>

#include <logging.h>
#include <script/script.h>

#include <vector>

// Helper: scan a single witness element for OP_FALSE OP_IF ... OP_ENDIF envelopes.
// Returns true if an inscription envelope is found.
static bool ScanForInscriptionEnvelope(const std::vector<unsigned char>& elem)
{
    const size_t len = elem.size();
    if (len < 3) return false; // Need at minimum OP_FALSE OP_IF OP_ENDIF

    size_t pos = 0;
    while (pos + 1 < len) {
        // Look for OP_FALSE (0x00) followed by OP_IF (0x63)
        if (elem[pos] == 0x00 && elem[pos + 1] == 0x63) {
            // Found OP_FALSE OP_IF — scan for matching OP_ENDIF
            pos += 2; // skip past OP_FALSE OP_IF
            int depth = 1;

            while (pos < len && depth > 0) {
                unsigned char op = elem[pos];
                switch (op) {
                case 0x63: // OP_IF
                case 0x64: // OP_NOTIF
                    depth++;
                    pos++;
                    break;
                case 0x68: // OP_ENDIF
                    depth--;
                    pos++;
                    break;
                // Skip push data inside dead region
                default:
                    if (op >= 0x01 && op <= 0x4b) {
                        // Direct push: op bytes follow
                        pos += 1 + static_cast<size_t>(op);
                    } else if (op == 0x4c) {
                        // OP_PUSHDATA1: 1-byte length prefix
                        if (pos + 1 < len) {
                            size_t skip = elem[pos + 1];
                            pos += 2 + skip;
                        } else {
                            pos = len;
                        }
                    } else if (op == 0x4d) {
                        // OP_PUSHDATA2: 2-byte length prefix (little-endian)
                        if (pos + 2 < len) {
                            size_t skip = static_cast<size_t>(elem[pos + 1]) |
                                          (static_cast<size_t>(elem[pos + 2]) << 8);
                            pos += 3 + skip;
                        } else {
                            pos = len;
                        }
                    } else if (op == 0x4e) {
                        // OP_PUSHDATA4: 4-byte length prefix (little-endian)
                        if (pos + 4 < len) {
                            size_t skip = static_cast<size_t>(elem[pos + 1]) |
                                          (static_cast<size_t>(elem[pos + 2]) << 8) |
                                          (static_cast<size_t>(elem[pos + 3]) << 16) |
                                          (static_cast<size_t>(elem[pos + 4]) << 24);
                            pos += 5 + skip;
                        } else {
                            pos = len;
                        }
                    } else {
                        pos++;
                    }
                    break;
                }
            }

            if (depth == 0) {
                return true; // Found complete OP_FALSE OP_IF ... OP_ENDIF
            }
        } else {
            // Skip forward through normal opcodes/pushes
            unsigned char op = elem[pos];
            if (op >= 0x01 && op <= 0x4b) {
                pos += 1 + static_cast<size_t>(op);
            } else if (op == 0x4c && pos + 1 < len) {
                pos += 2 + static_cast<size_t>(elem[pos + 1]);
            } else if (op == 0x4d && pos + 2 < len) {
                size_t skip = static_cast<size_t>(elem[pos + 1]) |
                              (static_cast<size_t>(elem[pos + 2]) << 8);
                pos += 3 + skip;
            } else if (op == 0x4e && pos + 4 < len) {
                size_t skip = static_cast<size_t>(elem[pos + 1]) |
                              (static_cast<size_t>(elem[pos + 2]) << 8) |
                              (static_cast<size_t>(elem[pos + 3]) << 16) |
                              (static_cast<size_t>(elem[pos + 4]) << 24);
                pos += 5 + skip;
            } else {
                pos++;
            }
        }
    }

    return false;
}

// Helper: scan a single witness element for large push followed by OP_DROP/OP_2DROP.
static bool ScanForDropStuffing(const std::vector<unsigned char>& elem, unsigned int min_drop_size)
{
    const size_t len = elem.size();
    if (len < 2) return false;

    size_t pos = 0;
    size_t prev_push_size = 0;

    while (pos < len) {
        unsigned char op = elem[pos];

        // OP_DROP (0x75) or OP_2DROP (0x6d) — check if preceded by large push
        if (op == 0x75 || op == 0x6d) {
            if (prev_push_size >= min_drop_size) {
                return true;
            }
            prev_push_size = 0;
            pos++;
            continue;
        }

        // Track push sizes
        if (op >= 0x01 && op <= 0x4b) {
            prev_push_size = static_cast<size_t>(op);
            pos += 1 + prev_push_size;
        } else if (op == 0x4c && pos + 1 < len) {
            prev_push_size = elem[pos + 1];
            pos += 2 + prev_push_size;
        } else if (op == 0x4d && pos + 2 < len) {
            prev_push_size = static_cast<size_t>(elem[pos + 1]) |
                             (static_cast<size_t>(elem[pos + 2]) << 8);
            pos += 3 + prev_push_size;
        } else if (op == 0x4e && pos + 4 < len) {
            prev_push_size = static_cast<size_t>(elem[pos + 1]) |
                             (static_cast<size_t>(elem[pos + 2]) << 8) |
                             (static_cast<size_t>(elem[pos + 3]) << 16) |
                             (static_cast<size_t>(elem[pos + 4]) << 24);
            pos += 5 + prev_push_size;
        } else {
            prev_push_size = 0;
            pos++;
        }
    }

    return false;
}

bool CheckInscriptionEnvelope(const CTransaction& tx, std::string& reason)
{
    for (size_t i = 0; i < tx.vin.size(); i++) {
        const auto& witness = tx.vin[i].scriptWitness;
        for (const auto& elem : witness.stack) {
            if (ScanForInscriptionEnvelope(elem)) {
                reason = "ghost-reaper-inscription-envelope";
                LogPrintLevel(BCLog::REAPER, BCLog::Level::Info, "Reaper: rejected tx %s input %zu — inscription envelope detected\n",
                         tx.GetHash().ToString(), i);
                return false;
            }
        }
    }
    return true;
}

bool CheckDropStuffing(const CTransaction& tx, unsigned int min_drop_size, std::string& reason)
{
    for (size_t i = 0; i < tx.vin.size(); i++) {
        const auto& witness = tx.vin[i].scriptWitness;
        for (const auto& elem : witness.stack) {
            if (ScanForDropStuffing(elem, min_drop_size)) {
                reason = "ghost-reaper-drop-stuffing";
                LogPrintLevel(BCLog::REAPER, BCLog::Level::Info, "Reaper: rejected tx %s input %zu — drop stuffing detected (min %u bytes)\n",
                         tx.GetHash().ToString(), i, min_drop_size);
                return false;
            }
        }
    }
    return true;
}

bool CheckFakeMultisigPubkeys(const CTransaction& tx, std::string& reason)
{
    for (size_t i = 0; i < tx.vout.size(); i++) {
        const CScript& script = tx.vout[i].scriptPubKey;
        const auto& bytes = std::vector<unsigned char>(script.begin(), script.end());
        const size_t len = bytes.size();

        if (len < 4) continue;

        // Check if script ends with OP_CHECKMULTISIG (0xae) or OP_CHECKMULTISIGVERIFY (0xaf)
        unsigned char last = bytes[len - 1];
        if (last != 0xae && last != 0xaf) continue;

        // First byte should be OP_1..OP_16 (0x51..0x60) for M
        unsigned char first = bytes[0];
        if (first < 0x51 || first > 0x60) continue;

        // Second-to-last byte should be OP_1..OP_16 for N
        unsigned char second_last = bytes[len - 2];
        if (second_last < 0x51 || second_last > 0x60) continue;

        unsigned int n = second_last - 0x50;

        // Walk pubkey pushes
        size_t pos = 1; // skip OP_M
        unsigned int pubkey_count = 0;

        while (pos < len - 2 && pubkey_count < n) {
            // Each pubkey push should be OP_PUSHBYTES_33 (0x21 = 33)
            if (bytes[pos] != 0x21) break;
            if (pos + 1 + 33 > len - 2) break;

            unsigned char prefix = bytes[pos + 1];
            if (prefix != 0x02 && prefix != 0x03) {
                reason = "ghost-reaper-fake-multisig-pubkey";
                LogPrintLevel(BCLog::REAPER, BCLog::Level::Info, "Reaper: rejected tx %s output %zu — fake pubkey prefix 0x%02x in bare multisig\n",
                         tx.GetHash().ToString(), i, prefix);
                return false;
            }

            pos += 1 + 33; // skip push opcode + 33 bytes
            pubkey_count++;
        }
    }
    return true;
}

bool CheckAnnexPresence(const CTransaction& tx, std::string& reason)
{
    for (size_t i = 0; i < tx.vin.size(); i++) {
        const auto& witness = tx.vin[i].scriptWitness;
        const auto& stack = witness.stack;

        // P2TR witness: at least 1 element. Annex is present when the last
        // stack element (before any tapscript) starts with 0x50.
        // Per BIP 341, the annex is the last element if it starts with 0x50
        // and the witness has at least 2 elements.
        if (stack.size() >= 2) {
            const auto& last = stack.back();
            if (!last.empty() && last[0] == 0x50) {
                reason = "ghost-reaper-annex-presence";
                LogPrintLevel(BCLog::REAPER, BCLog::Level::Info, "Reaper: rejected tx %s input %zu — P2TR annex detected\n",
                         tx.GetHash().ToString(), i);
                return false;
            }
        }
    }
    return true;
}

bool CheckOversizedOpReturn(const CTransaction& tx, unsigned int max_bytes, std::string& reason)
{
    for (size_t i = 0; i < tx.vout.size(); i++) {
        const CScript& script = tx.vout[i].scriptPubKey;
        if (!script.IsUnspendable()) continue;

        // Check if it starts with OP_RETURN (0x6a)
        if (script.size() < 1 || script[0] != OP_RETURN) continue;

        // Data payload = everything after OP_RETURN opcode
        size_t data_size = script.size() - 1;
        if (data_size > max_bytes) {
            reason = "ghost-reaper-oversized-opreturn";
            LogPrintLevel(BCLog::REAPER, BCLog::Level::Info, "Reaper: rejected tx %s output %zu — OP_RETURN %zu bytes exceeds limit %u\n",
                     tx.GetHash().ToString(), i, data_size, max_bytes);
            return false;
        }
    }
    return true;
}

bool CheckRunestone(const CTransaction& tx, std::string& reason)
{
    for (size_t i = 0; i < tx.vout.size(); i++) {
        const CScript& script = tx.vout[i].scriptPubKey;
        // Runestone signature: OP_RETURN (0x6a) followed by OP_13 (0x5d).
        // When OP_13 appears as a standalone opcode (not inside a data push)
        // immediately after OP_RETURN, the output is a Runestone per the
        // protocol's canonical encoding.
        if (script.size() >= 2 && script[0] == 0x6a && script[1] == 0x5d) {
            reason = "ghost-reaper-runestone";
            LogPrintLevel(BCLog::REAPER, BCLog::Level::Info, "Reaper: rejected tx %s output %zu — Runestone (OP_RETURN OP_13) detected\n",
                     tx.GetHash().ToString(), i);
            return false;
        }
    }
    return true;
}

bool IsGhostReaperClean(const CTransaction& tx, const GhostReaperConfig& config, std::string& reason)
{
    // Each detector runs only when its per-vector toggle is enabled.
    // Order: cheapest checks first.

    if (config.reject_opreturn && !CheckOversizedOpReturn(tx, config.max_op_return_bytes, reason)) {
        return false;
    }

    if (config.reject_runestone && !CheckRunestone(tx, reason)) {
        return false;
    }

    if (config.reject_fakepubkey && !CheckFakeMultisigPubkeys(tx, reason)) {
        return false;
    }

    if (config.reject_annex && !CheckAnnexPresence(tx, reason)) {
        return false;
    }

    if (config.reject_dropstuffing && !CheckDropStuffing(tx, config.min_drop_size, reason)) {
        return false;
    }

    if (config.reject_inscription && !CheckInscriptionEnvelope(tx, reason)) {
        return false;
    }

    return true;
}

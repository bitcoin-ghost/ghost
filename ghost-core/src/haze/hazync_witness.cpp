// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <haze/hazync_witness.h>

#include <chain.h>
#include <common/args.h>
#include <core_io.h>
#include <crypto/hex_base.h>
#include <logging.h>
#include <primitives/block.h>
#include <util/fs.h>
#include <util/fs_helpers.h>

#include <cstdio>
#include <sstream>
#include <string>

namespace haze {

std::unique_ptr<HazyncWitnessEmitter> HazyncWitnessEmitter::MaybeCreate(const ArgsManager& args)
{
    const std::string dir{args.GetArg("-hazyncwitness", "")};
    if (dir.empty()) return nullptr;
    fs::path out_dir{fs::PathFromString(dir)};
    // Core deletes the std::error_code fs overloads; use the throwing one (guarded).
    try {
        fs::create_directories(out_dir);
    } catch (const fs::filesystem_error& e) {
        LogError("hazync: cannot create witness dir %s: %s\n", dir, e.what());
        return nullptr;
    }
    LogInfo("hazync: emitting block witnesses to %s\n", fs::PathToString(out_dir));
    return std::make_unique<HazyncWitnessEmitter>(std::move(out_dir));
}

void HazyncWitnessEmitter::WriteBlock(const CBlock& block, const CBlockIndex& pindex,
                                      const std::vector<std::vector<InputMeta>>& spent) const
{
    // Hand-build the JSON: every value is a number or a hex string (no characters that need escaping),
    // so a stream is safe and keeps this module dependency-light. Shape matches prover/fetch_block.py.
    std::ostringstream o;
    o << '{'
      << "\"height\":" << pindex.nHeight
      << ",\"version\":" << block.nVersion
      << ",\"time\":" << block.nTime
      << ",\"bits\":" << block.nBits
      << ",\"nonce\":" << block.nNonce
      << ",\"prev\":\"" << block.hashPrevBlock.ToString() << '"'
      << ",\"merkle\":\"" << block.hashMerkleRoot.ToString() << '"'
      << ",\"coinbase_hex\":\"" << EncodeHexTx(*block.vtx[0]) << '"'
      << ",\"txs\":[";

    bool first_tx{true};
    for (size_t i = 1; i < block.vtx.size(); ++i) {
        if (!first_tx) o << ',';
        first_tx = false;
        o << "{\"raw\":\"" << EncodeHexTx(*block.vtx[i]) << "\",\"prevouts\":[";
        const std::vector<InputMeta>& ins{spent[i]};
        for (size_t j = 0; j < ins.size(); ++j) {
            if (j) o << ',';
            const InputMeta& m{ins[j]};
            o << "{\"value\":" << m.value
              << ",\"spk\":\"" << HexStr(m.scriptPubKey) << '"'
              << ",\"coin_height\":" << m.coin_height
              << ",\"coin_is_coinbase\":" << (m.coin_is_coinbase ? 1 : 0)
              << ",\"coin_mtp\":" << m.coin_mtp
              << '}';
        }
        o << "]}";
    }
    o << "]}";

    // Write atomically: tmp file then rename, so a partially written file is never picked up.
    const std::string name{"block_" + std::to_string(pindex.nHeight) + ".json"};
    const fs::path final_path{m_out_dir / fs::PathFromString(name)};
    const fs::path tmp_path{m_out_dir / fs::PathFromString(name + ".tmp")};
    {
        FILE* f{fsbridge::fopen(tmp_path, "wb")};
        if (!f) {
            LogError("hazync: cannot open %s\n", fs::PathToString(tmp_path));
            return;
        }
        const std::string s{o.str()};
        const bool ok{std::fwrite(s.data(), 1, s.size(), f) == s.size()};
        std::fclose(f);
        if (!ok) {
            LogError("hazync: short write to %s\n", fs::PathToString(tmp_path));
            return;
        }
    }
    if (!RenameOver(tmp_path, final_path)) {
        LogError("hazync: cannot rename %s -> %s\n", fs::PathToString(tmp_path), fs::PathToString(final_path));
    }
}

} // namespace haze

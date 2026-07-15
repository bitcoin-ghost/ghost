# Copyright (c) 2026 The Bitcoin Ghost developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# Ghost Haze module
# Phase 1: Stripped block format, field classification, block stripping,
#           Ghost Exorcism (strip-before-write), and Ghost Exorcist (archive conversion).
# Phase 2: Checkpoint format, Ed25519 signing, SwiftSync Bloom filter,
#           parallel chunk download.
# Phase 3: Mode selection, RPC compatibility, legal compliance, P2P messages.

add_library(bitcoin_haze STATIC EXCLUDE_FROM_ALL
  # Phase 1: Core Engine
  field_classifier.cpp
  stripped_block.cpp
  block_stripper.cpp
  exorcism.cpp
  exorcist.cpp
  # Phase 2: Checkpoint & Sync
  checkpoint.cpp
  headers_file.cpp
  checkpoint_signing.cpp
  bloom_filter.cpp
  swiftsync.cpp
  chunk_downloader.cpp
  # Phase 3: Integration
  mode_selector.cpp
  block_reconstruct.cpp
  legal_packet.cpp
  haze_p2p.cpp
  # Hazync: archive-node bridge (per-block zkVM prover witness emitter)
  hazync_witness.cpp
)

target_include_directories(bitcoin_haze
  PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(bitcoin_haze
  PRIVATE
    core_interface
    bitcoin_common
    bitcoin_consensus
    bitcoin_util
    bitcoin_crypto_ed25519
    univalue
)

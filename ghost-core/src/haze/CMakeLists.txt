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
  hazync_proof.cpp
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

# ── Hazync proof verification (optional) ───────────────────────────────────────────────────────────
# Links the Hazync proof verifier from the hazync repo via its C ABI. OFF by default: a node that
# cannot verify a proof simply validates everything itself, which is the status quo and always safe.
#
# Deliberately NOT reimplemented in C++. Verifying a risc0 receipt means Groth16 over BN254 plus
# risc0's receipt and claim format; a second implementation would be a large body of
# consensus-critical code that would drift from the one hazync's CI exercises on every push.
#
#   cmake -DWITH_HAZYNC_VERIFY=ON \
#         -DHAZYNC_VERIFY_LIB=/path/to/libhazync_verify.a \
#         -DHAZYNC_VERIFY_INCLUDE=/path/to/hazync/verifier-ffi/include
option(WITH_HAZYNC_VERIFY "Link the Hazync proof verifier (requires a prebuilt libhazync_verify.a)" OFF)
if(WITH_HAZYNC_VERIFY)
  if(NOT HAZYNC_VERIFY_LIB OR NOT EXISTS "${HAZYNC_VERIFY_LIB}")
    message(FATAL_ERROR "WITH_HAZYNC_VERIFY=ON requires -DHAZYNC_VERIFY_LIB=<path to libhazync_verify.a>. "
                        "Build it with: cargo build --release --manifest-path verifier-ffi/Cargo.toml")
  endif()
  if(NOT HAZYNC_VERIFY_INCLUDE OR NOT EXISTS "${HAZYNC_VERIFY_INCLUDE}/hazync_verify.h")
    message(FATAL_ERROR "WITH_HAZYNC_VERIFY=ON requires -DHAZYNC_VERIFY_INCLUDE=<dir containing hazync_verify.h>")
  endif()
  target_compile_definitions(bitcoin_haze PUBLIC WITH_HAZYNC_VERIFY)
  target_include_directories(bitcoin_haze PUBLIC "${HAZYNC_VERIFY_INCLUDE}")
  target_link_libraries(bitcoin_haze PUBLIC "${HAZYNC_VERIFY_LIB}" pthread dl m)
  message(STATUS "Hazync proof verification: ENABLED (${HAZYNC_VERIFY_LIB})")
endif()

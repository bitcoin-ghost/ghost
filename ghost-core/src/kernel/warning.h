// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_WARNING_H
#define BITCOIN_KERNEL_WARNING_H

namespace kernel {
enum class Warning {
    UNKNOWN_NEW_RULES_ACTIVATED,
    LARGE_WORK_INVALID_CHAIN,
    //! A hazed node needs a block it destroyed and no peer has supplied a copy.
    //! Not a transient condition: it is a designed state the operator has to resolve,
    //! so it is surfaced rather than left as a log line that scrolls away.
    HAZE_BLOCK_UNAVAILABLE,
};
} // namespace kernel
#endif // BITCOIN_KERNEL_WARNING_H

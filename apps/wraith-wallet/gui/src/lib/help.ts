// Plain-language help copy, kept in one place so the three help
// layers never drift out of sync:
//
//   1. Per-category explainers — the "?" beside each sidebar group
//      heading reveals CATEGORY_HELP[heading].
//   2. Contextual "What's this?" tips — the HelpTip affordance on
//      Send / Locks / Mix / Merchant / the seed step reads HELP_TOPICS.
//   3. First-run tour — walks the four categories, reusing the same
//      CATEGORY_HELP text so the tour and the sidebar agree word-for-word.
//
// Everything here is beginner-first: no jargon that isn't immediately
// explained, British spelling, one to four short sentences each.

/// Keyed by the sidebar group heading in App.tsx `NAV_GROUPS`.
/// One or two sentences: "what this is / what you can do here".
export const CATEGORY_HELP: Record<string, string> = {
  Wallet:
    "Your money and its history live here. Create or restore a wallet, watch your balance and past payments, and time-lock funds so they can only be spent later.",
  Payments:
    "Send and receive money here. Pay instantly and fee-free off-chain with Ghost Pay, or make a normal on-chain Bitcoin payment. You can also sign transactions and mix coins for privacy.",
  Merchant:
    "Take payments as a shop or stall. Show a customer a QR code, watch it flip to paid, and export tidy sales reports for your records.",
  System:
    "Settings and health. Choose which Ghost node the wallet connects to, back up your wallet file, check for updates, and see how the wallet is doing.",
};

/// Contextual tips surfaced by the HelpTip "?" affordance. Two to four
/// sentences, jargon-light. `title` shows as the popover heading.
export interface HelpTopic {
  title: string;
  body: string;
}

export const HELP_TOPICS: Record<string, HelpTopic> = {
  send: {
    title: "Ghost Pay (L2) vs on-chain (L1)",
    body:
      "Ghost Pay is a Layer 2 (L2) transfer: it settles instantly between Ghost wallets with no network fee, ideal for everyday spending. On-chain is Layer 1 (L1): a normal Bitcoin transaction that anyone can verify on the blockchain, but it pays a miner fee and takes time to confirm. Start with Ghost Pay; switch to on-chain (PSBT) when you're paying a plain Bitcoin address or moving funds off the network.",
  },
  locks: {
    title: "What is a time-lock?",
    body:
      "A time-lock puts coins into an output that can't be spent until a chosen future point. It's a self-custody safety tool — think of it as a savings jar you set to open on a certain date. Because the lock uses the same shape as a CoinJoin output, it also blends you in with others for privacy, and you can always recover the funds yourself once the lock matures.",
  },
  mix: {
    title: "What is mixing (CoinJoin)?",
    body:
      "Mixing joins your coins with other people's in a single transaction, so an outside observer can't tell which output belongs to whom. This breaks the link between your old coins and your new ones, giving you on-chain privacy. Nobody takes custody of your money during a mix — you always keep control of your own keys.",
  },
  merchant: {
    title: "How taking a payment works",
    body:
      "Add up an amount, and the wallet shows the customer a QR code to scan. When their payment lands, the screen flips to PAID on its own — no need to refresh or check manually. Every sale is recorded so you can export a report later from the Reports screen.",
  },
  mnemonic: {
    title: "Why write down your recovery phrase?",
    body:
      "These words are the only complete backup of your wallet. If your computer is lost, stolen, or wiped, typing this phrase into any Ghost wallet restores your money in full. Write it on paper and store it somewhere safe and private — never a photo or a cloud note. Anyone who reads it can spend your funds, and nobody, not even us, can recover it for you if it's lost.",
  },
};

import { useMemo, useState } from "react";
import { walletCreate, walletImport } from "../lib/tauri";
import { Logo } from "../components/Logo";
import { HelpTip } from "../components/HelpTip";
import { HELP_TOPICS } from "../lib/help";

interface OnboardingProps {
  /// "create" launches the create-new flow; "import" launches the
  /// import-from-mnemonic flow. The two paths share the modal
  /// shell but differ in their middle steps.
  mode: "create" | "import";
  /// Called when the wizard finishes (wallet was created/imported)
  /// or the user cancels. The parent re-fetches the wallet list.
  onClose: () => void;
}

/// Bits per event, matching `ghost_entropy`. These are for the live counter
/// only — `UserEntropy::digest` is the authority and refuses below the floor
/// regardless of what this displays. They are duplicated rather than fetched
/// because a progress bar must not need a round trip per keystroke.
const BITS_PER_DIE_ROLL = 2.584962500721156;
const BITS_PER_COIN_FLIP = 1.0;
/// Least contribution accepted at all: 128 bits, i.e. 50 rolls or 128 flips.
const MIN_USER_BITS = 128.0;
/// A full-strength contribution, matching the 256-bit seed: 99 rolls.
const RECOMMENDED_USER_BITS = 256.0;

/// Count what the user has typed so far, and name the first character that is
/// not a die face, a coin or whitespace.
///
/// Reports the offending character rather than dropping it, because the Rust
/// parser refuses it: if this skipped what that rejects, the counter would say
/// the user was finished and the create would then fail.
function tallyRolls(input: string): {
  dieRolls: number;
  coinFlips: number;
  bits: number;
  badChar: string | null;
} {
  let dieRolls = 0;
  let coinFlips = 0;
  let badChar: string | null = null;
  for (const ch of input) {
    if (/\s/.test(ch)) continue;
    if (ch >= "1" && ch <= "6") dieRolls++;
    else if (ch === "h" || ch === "H" || ch === "t" || ch === "T") coinFlips++;
    else if (badChar === null) badChar = ch;
  }
  return {
    dieRolls,
    coinFlips,
    bits: dieRolls * BITS_PER_DIE_ROLL + coinFlips * BITS_PER_COIN_FLIP,
    badChar,
  };
}

type Step =
  | "welcome"
  | "name_pass"
  | "dice"
  | "show_mnemonic"
  | "confirm_mnemonic"
  | "enter_mnemonic"
  | "submitting"
  | "done";

/// Multi-step onboarding wizard. Replaces every former `prompt()`
/// dialog with proper UI, and adds a backup-verification step
/// before the create flow finishes — best practice in any wallet
/// that doesn't ship hardware seed cards.
///
/// Two paths share the shell:
///   create:  welcome → name+pass → daemon-create returns mnemonic
///         →  show all 24 words → user types 3 random ones back
///         →  done
///   import:  welcome → name+pass → enter mnemonic → daemon-import
///         →  done
export function Onboarding({ mode, onClose }: OnboardingProps) {
  const [step, setStep] = useState<Step>("welcome");
  const [name, setName] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [passphraseConfirm, setPassphraseConfirm] = useState("");
  const [mnemonic, setMnemonic] = useState(""); // import-mode input
  const [generatedMnemonic, setGeneratedMnemonic] = useState<string | null>(
    null,
  );
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // Backup-confirm step: pick 3 random word-positions and ask the
  // user to type them back. Fast enough to prove they wrote the
  // phrase down without being adversarial about typos.
  const verifyPositions = useMemo(() => {
    if (!generatedMnemonic) return [] as number[];
    const len = generatedMnemonic.split(/\s+/).length;
    const all = Array.from({ length: len }, (_, i) => i);
    // Deterministic shuffle seeded by the mnemonic itself so the
    // step is stable across re-renders within one wizard session.
    let seed = 0;
    for (const ch of generatedMnemonic) seed = (seed * 31 + ch.charCodeAt(0)) >>> 0;
    for (let i = all.length - 1; i > 0; i--) {
      seed = (seed * 1664525 + 1013904223) >>> 0;
      const j = seed % (i + 1);
      [all[i], all[j]] = [all[j], all[i]];
    }
    return all.slice(0, 3).sort((a, b) => a - b);
  }, [generatedMnemonic]);
  const [verifyInputs, setVerifyInputs] = useState<string[]>(["", "", ""]);
  /// Opt-in, and off by default on purpose: mixing means no rolls costs the
  /// user nothing, so the ordinary path must not be the one with extra steps.
  const [useDice, setUseDice] = useState(false);
  const [rolls, setRolls] = useState("");
  const tally = useMemo(() => tallyRolls(rolls), [rolls]);

  const validateNamePass = (): string | null => {
    if (!name.trim()) return "Wallet name is required.";
    if (!/^[A-Za-z0-9._-]+$/.test(name.trim())) {
      return "Wallet name can only contain letters, numbers, dot, underscore, hyphen.";
    }
    if (passphrase.length < 8) {
      return "Passphrase must be at least 8 characters.";
    }
    if (passphrase !== passphraseConfirm) {
      return "Passphrases don't match.";
    }
    return null;
  };

  const onSubmitNamePass = async () => {
    const v = validateNamePass();
    if (v) {
      setErr(v);
      return;
    }
    setErr(null);
    if (mode === "create") {
      if (useDice) {
        setStep("dice");
        return;
      }
      await doCreate(undefined, "name_pass");
    } else {
      setStep("enter_mnemonic");
    }
  };

  /// Create the wallet, returning the user to `backTo` if the daemon refuses.
  ///
  /// `rollsArg` is the raw sequence, never a digest — the Rust command hashes it
  /// in-process so the construction exists once and the 128-bit floor stays
  /// enforceable. An empty or absent value means the user declined, which is a
  /// supported choice and not a degraded one.
  const doCreate = async (rollsArg: string | undefined, backTo: Step) => {
    setBusy(true);
    setStep("submitting");
    try {
      const r = await walletCreate(name.trim(), passphrase, rollsArg);
      // Clear the sequence as soon as it has been used. It reconstructs the
      // contribution, so it is key material for as long as it is held; the Rust
      // side zeroizes its own copy on drop.
      setRolls("");
      setGeneratedMnemonic(r.mnemonic);
      setStep("show_mnemonic");
    } catch (e) {
      setErr((e as Error).message ?? String(e));
      setStep(backTo);
    } finally {
      setBusy(false);
    }
  };

  const onSubmitMnemonic = async () => {
    const cleaned = mnemonic
      .split(/\s+/)
      .filter((w) => w.length > 0)
      .join(" ");
    const wordCount = cleaned.split(" ").length;
    if (wordCount !== 12 && wordCount !== 24) {
      setErr(`Expected 12 or 24 words, got ${wordCount}.`);
      return;
    }
    setErr(null);
    setBusy(true);
    setStep("submitting");
    try {
      await walletImport(name.trim(), cleaned, passphrase);
      setStep("done");
    } catch (e) {
      setErr((e as Error).message ?? String(e));
      setStep("enter_mnemonic");
    } finally {
      setBusy(false);
    }
  };

  const onAckMnemonic = () => {
    setStep("confirm_mnemonic");
  };

  const onSubmitVerify = () => {
    if (!generatedMnemonic) return;
    const words = generatedMnemonic.split(/\s+/);
    for (let i = 0; i < verifyPositions.length; i++) {
      const expected = words[verifyPositions[i]];
      const got = verifyInputs[i].trim().toLowerCase();
      if (got !== expected) {
        setErr(
          `Word ${verifyPositions[i] + 1} doesn't match — check your written copy and try again.`,
        );
        return;
      }
    }
    setErr(null);
    setStep("done");
  };

  const copy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* ignore */
    }
  };

  if (step === "done") {
    onClose();
    return null;
  }

  return (
    <div className="modal-overlay">
      <div className="modal-card" onClick={(e) => e.stopPropagation()}>
        <div className="card-header">
          <div className="row" style={{ gap: 10, alignItems: "center" }}>
            <Logo size={22} />
            <h2 style={{ margin: 0 }}>
              {mode === "create" ? "New wallet" : "Import wallet"}
            </h2>
          </div>
          {step !== "welcome" && (
            <span className="eyebrow eyebrow-dim">
              {stepLabel(mode, step)}
            </span>
          )}
        </div>

        {err && (
          <div className="pill fail" style={{ alignSelf: "flex-start" }}>
            {err}
          </div>
        )}

        {step === "welcome" && (
          <>
            <p className="muted" style={{ margin: 0 }}>
              {mode === "create"
                ? "Create a fresh wallet with a new BIP-39 backup phrase. The phrase is shown ONCE — write it on paper, then we'll ask you to verify a few words before continuing."
                : "Restore an existing wallet from its 12 or 24 word BIP-39 backup phrase. The mnemonic is sent over the local IPC socket and encrypted at rest with your passphrase — never over the network."}
            </p>
            <div className="row" style={{ marginTop: 8, justifyContent: "flex-end", gap: 8 }}>
              <button className="btn-secondary" onClick={onClose}>
                Cancel
              </button>
              <button
                className="btn-primary"
                onClick={() => setStep("name_pass")}
              >
                Continue →
              </button>
            </div>
          </>
        )}

        {step === "name_pass" && (
          <>
            <div className="col">
              <label>Wallet name</label>
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                disabled={busy}
                placeholder="personal, merchant-till-1, …"
                autoFocus
              />
            </div>
            <div className="col">
              <label>Passphrase</label>
              <input
                type="password"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                disabled={busy}
                placeholder="At least 8 characters"
              />
            </div>
            <div className="col">
              <label>Confirm passphrase</label>
              <input
                type="password"
                value={passphraseConfirm}
                onChange={(e) => setPassphraseConfirm(e.target.value)}
                disabled={busy}
                onKeyDown={(e) => {
                  if (e.key === "Enter") onSubmitNamePass();
                }}
              />
            </div>
            <p className="muted" style={{ margin: 0, fontSize: 12 }}>
              The passphrase encrypts the keystore at rest. It does
              NOT replace your backup phrase — losing the passphrase
              means losing the wallet unless you have the mnemonic.
            </p>
            {mode === "create" && (
              <label
                className="row"
                style={{ gap: 8, alignItems: "flex-start", cursor: "pointer" }}
              >
                <input
                  type="checkbox"
                  checked={useDice}
                  onChange={(e) => setUseDice(e.target.checked)}
                  disabled={busy}
                  style={{ marginTop: 3 }}
                />
                <span style={{ fontSize: 12 }}>
                  Mix in my own dice rolls
                  <span className="muted">
                    {" "}
                    — optional. Your rolls are combined with this computer's
                    randomness, never used instead of it, so skipping this
                    costs you nothing.
                  </span>
                </span>
              </label>
            )}
            <div className="row" style={{ justifyContent: "flex-end", gap: 8 }}>
              <button
                className="btn-secondary"
                onClick={() => setStep("welcome")}
              >
                Back
              </button>
              <button
                className="btn-primary"
                onClick={onSubmitNamePass}
                disabled={busy}
              >
                Continue →
              </button>
            </div>
          </>
        )}

        {step === "dice" && (
          <>
            <p className="muted" style={{ margin: 0, fontSize: 12 }}>
              Your dice are <strong>mixed</strong> with the randomness this
              computer produces — they are never used instead of it. So your
              rolls can only help: if the operating system's random source were
              ever weak, your rolls still stand between an attacker and your
              coins, and if your rolls are poor the seed is exactly as strong as
              it would have been.
            </p>
            <ul className="muted" style={{ margin: 0, fontSize: 12, paddingLeft: 18 }}>
              <li>
                Type <code>1</code>–<code>6</code> for dice, <code>h</code> or{" "}
                <code>t</code> for coin flips. Spaces and newlines are ignored,
                so group them however you like.
              </li>
              <li>
                Enter <strong>every</strong> roll, including repeats. A run of
                the same number is normal — discarding results you dislike is
                what makes a sequence predictable.
              </li>
              <li>
                Never use a sequence you can remember or that means something (a
                birthday, a phone number). Anything memorable is guessable.
              </li>
              <li>
                Nobody should be watching, and this screen should not be
                recorded or screenshotted.
              </li>
            </ul>
            <div className="col">
              <label>Your rolls</label>
              <textarea
                value={rolls}
                onChange={(e) => setRolls(e.target.value)}
                disabled={busy}
                rows={5}
                autoFocus
                spellCheck={false}
                autoComplete="off"
                placeholder="41325 66214 53121 …"
                style={{ fontFamily: "monospace", letterSpacing: "0.08em" }}
              />
            </div>
            <div className="col" style={{ gap: 4 }}>
              <div
                style={{
                  height: 6,
                  borderRadius: 3,
                  background: "var(--border, #333)",
                  overflow: "hidden",
                }}
              >
                <div
                  style={{
                    height: "100%",
                    width: `${Math.min(100, (tally.bits / RECOMMENDED_USER_BITS) * 100)}%`,
                    background:
                      tally.bits >= MIN_USER_BITS
                        ? "var(--ok, #3fb950)"
                        : "var(--warn, #d29922)",
                    transition: "width 120ms linear",
                  }}
                />
              </div>
              <p className="muted" style={{ margin: 0, fontSize: 12 }}>
                {tally.bits.toFixed(0)} of {RECOMMENDED_USER_BITS} bits ·{" "}
                {tally.dieRolls} rolls, {tally.coinFlips} flips
                {tally.bits < MIN_USER_BITS ? (
                  <>
                    {" "}
                    — {Math.ceil((MIN_USER_BITS - tally.bits) / BITS_PER_DIE_ROLL)}{" "}
                    more rolls to reach the {MIN_USER_BITS}-bit minimum
                  </>
                ) : tally.bits < RECOMMENDED_USER_BITS ? (
                  <>
                    {" "}
                    — enough to accept.{" "}
                    {Math.ceil(
                      (RECOMMENDED_USER_BITS - tally.bits) / BITS_PER_DIE_ROLL,
                    )}{" "}
                    more reaches full strength.
                  </>
                ) : (
                  <> — full strength.</>
                )}
              </p>
            </div>
            {tally.badChar !== null && (
              <p style={{ margin: 0, fontSize: 12, color: "var(--warn, #d29922)" }}>
                "{tally.badChar}" is not a die face (1–6), a coin (h/t), or a
                space. Remove it — it will be refused rather than skipped.
              </p>
            )}
            <div className="row" style={{ justifyContent: "space-between", gap: 8 }}>
              <button
                className="btn-secondary"
                onClick={() => {
                  setRolls("");
                  setUseDice(false);
                  setErr(null);
                  void doCreate(undefined, "dice");
                }}
                disabled={busy}
                title="Create the wallet from this computer's randomness alone"
              >
                Skip
              </button>
              <div className="row" style={{ gap: 8 }}>
                <button
                  className="btn-secondary"
                  onClick={() => setStep("name_pass")}
                  disabled={busy}
                >
                  Back
                </button>
                <button
                  className="btn-primary"
                  onClick={() => {
                    setErr(null);
                    void doCreate(rolls, "dice");
                  }}
                  disabled={
                    busy || tally.bits < MIN_USER_BITS || tally.badChar !== null
                  }
                >
                  Create wallet →
                </button>
              </div>
            </div>
          </>
        )}

        {step === "show_mnemonic" && generatedMnemonic && (
          <>
            <div className="card warn" style={{ margin: 0 }}>
              <p style={{ margin: 0 }}>
                <strong>Write these 24 words on paper.</strong>{" "}
                <HelpTip
                  title={HELP_TOPICS.mnemonic.title}
                  label="Why write down the recovery phrase"
                >
                  {HELP_TOPICS.mnemonic.body}
                </HelpTip>{" "}
                Anyone with this phrase can spend funds in this wallet.
                The daemon doesn't keep it in plaintext anywhere —
                without it, recovery is impossible if the keystore file
                or its passphrase are lost.
              </p>
              <div className="mnemonic-block">
                {generatedMnemonic
                  .trim()
                  .split(/\s+/)
                  .map((w, i) => (
                    <div className="mnemonic-word" key={i}>
                      <span className="mnemonic-idx">{i + 1}</span>
                      <span className="mnemonic-text">{w}</span>
                    </div>
                  ))}
              </div>
              <button
                className="btn-secondary btn-sm"
                onClick={() => copy(generatedMnemonic)}
                style={{ alignSelf: "flex-start" }}
              >
                {copied ? "copied" : "Copy to clipboard"}
              </button>
            </div>
            <div className="row" style={{ justifyContent: "flex-end" }}>
              <button
                className="btn-primary"
                onClick={onAckMnemonic}
              >
                I have written it down →
              </button>
            </div>
          </>
        )}

        {step === "confirm_mnemonic" && generatedMnemonic && (
          <>
            <p className="muted" style={{ margin: 0 }}>
              Quick check: type back the words at these positions
              from your written copy. Catches a hand-copy slip
              before you lock the keystore.
            </p>
            <div className="col" style={{ gap: 8 }}>
              {verifyPositions.map((pos, idx) => (
                <div className="row" key={pos} style={{ alignItems: "baseline" }}>
                  <label
                    style={{
                      width: 90,
                      flexShrink: 0,
                      textTransform: "none",
                      letterSpacing: 0,
                      fontFamily: "var(--font-mono)",
                      fontSize: 13,
                      color: "var(--dim)",
                    }}
                  >
                    Word #{pos + 1}
                  </label>
                  <input
                    className="mono"
                    value={verifyInputs[idx]}
                    onChange={(e) => {
                      const next = [...verifyInputs];
                      next[idx] = e.target.value;
                      setVerifyInputs(next);
                    }}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" && idx === verifyPositions.length - 1)
                        onSubmitVerify();
                    }}
                    autoFocus={idx === 0}
                  />
                </div>
              ))}
            </div>
            <div className="row" style={{ justifyContent: "space-between", gap: 8 }}>
              <button
                className="btn-secondary btn-sm"
                onClick={() => setStep("show_mnemonic")}
              >
                ← Show phrase again
              </button>
              <button className="btn-primary" onClick={onSubmitVerify}>
                Verify
              </button>
            </div>
          </>
        )}

        {step === "enter_mnemonic" && (
          <>
            <div className="col">
              <label>BIP-39 mnemonic</label>
              <textarea
                value={mnemonic}
                onChange={(e) => setMnemonic(e.target.value)}
                disabled={busy}
                placeholder="word1 word2 word3 ... (12 or 24 words)"
                rows={3}
                className="mono"
                autoFocus
              />
            </div>
            <p className="muted" style={{ margin: 0, fontSize: 12 }}>
              Whitespace is normalised — paste from any line wrapping.
              Sent over the local IPC socket only; encrypted at rest
              with your passphrase.
            </p>
            <div className="row" style={{ justifyContent: "flex-end", gap: 8 }}>
              <button
                className="btn-secondary"
                onClick={() => setStep("name_pass")}
                disabled={busy}
              >
                Back
              </button>
              <button
                className="btn-primary"
                onClick={onSubmitMnemonic}
                disabled={busy}
              >
                {busy ? "Importing…" : "Import"}
              </button>
            </div>
          </>
        )}

        {step === "submitting" && (
          <div
            style={{
              padding: 32,
              textAlign: "center",
              color: "var(--dim)",
              fontFamily: "var(--font-mono)",
              fontSize: 13,
              letterSpacing: "0.08em",
              textTransform: "uppercase",
            }}
          >
            working…
          </div>
        )}
      </div>
    </div>
  );
}

function stepLabel(mode: "create" | "import", step: Step): string {
  if (mode === "create") {
    if (step === "name_pass") return "step 1 of 3";
    if (step === "dice") return "optional · your own dice";
    if (step === "show_mnemonic") return "step 2 of 3 · backup";
    if (step === "confirm_mnemonic") return "step 3 of 3 · verify";
    return "";
  }
  if (step === "name_pass") return "step 1 of 2";
  if (step === "enter_mnemonic") return "step 2 of 2 · restore";
  return "";
}

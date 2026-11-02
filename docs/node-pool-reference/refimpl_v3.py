"""Normative integer reference, draft 3.1 (W1.3): exact pay with the top balance as remainder absorber.
Python ints only, no floats. Draft 3.0 (the draft 7/8 rule, no absorber) is kept as build_outputs_draft8/select_draft8.
Run directly to self-test and write test_vectors_v3.json. refimpl_v2.py (draft 6, floating ratio) is kept unchanged.

Unit: 1 face unit = 2^-32 sat. A "face" is what a share was worth at its own difficulty.

The rule (user decision):
  S = subsidy(H); Rm = S - S/200
  owed[a] = sum(face) - sum(retired)        table at cut(H) = H - 20, retired through tip H - 1
  eligible = owed >= 1,000 sats (FLOOR face units)
  N = miner outputs of the job's slot class; O = ceil(N/2) oldest, L = N - O largest
  top     = the single largest eligible balance, by (owed desc, script asc): the remainder absorber
  oldest  = eligible except top, by (queue_since asc, owed desc, script asc), first O
  largest = [top] + rest of eligible by (owed desc, script asc), first L in all (top is its first entry)
  pay every selected payee EXCEPT top, oldest first then largest: pay = min(owed, Rm left);
      stop when Rm left < 1,000 sats
  then top: pay = min(owed_top, Rm left) if that is >= 1,000 sats
  retired = pay, exactly
  treasury = S/200 + (Rm - sum(pay))
No K_R, no X, no x, no ratio. Nobody is paid more than owed.

Integer details that the prose leaves open, fixed here:
  * pay is in whole sats: pay = min(owed // 2^32, Rm_left). retired = pay * 2^32 face units exactly. The sub-sat
    remainder of a fully paid balance stays owed (it is below the floor, so queue_since clears).
  * "stop when Rm left < 1,000 sats" is tested BEFORE each payee. Since every eligible owed is >= 1,000 sats, every
    paid output is >= 1,000 sats, and at most one payee (the last output) is paid in part.
  * miner outputs appear in pay order: the oldest list in queue order, then the largest list without top, then
    top LAST among the miner outputs. With one eligible balance, it is top and is paid min(owed, Rm).
  * top is reserved before the oldest are chosen, so it is never also in the oldest list.
  * queue_since = the credit (share) height of the batch that took owed to >= FLOOR; it is reset to None only when
    owed falls below FLOOR. A batch of credits at share height c becomes visible at table height c + 20.
  * the commitment OP_RETURN carries the table root only; there is no x any more.
"""
import hashlib, json, os, random, sys

COIN_SUBSIDY0 = 5_000_000_000
HALVING = 210_000
TREASURY_DIV = 200            # 0.5%
MIN_PAY = 1_000               # sats
ONE = 1 << 32
FLOOR = MIN_PAY * ONE         # 1,000 sats in face units
CUT_LAG = 20                  # cut(H) = H - 20, fixed
SLOT_CLASSES = {0: 3, 1: 9, 2: 44, 3: 143, 4: 364, 5: 500}   # miner outputs per class (spec 2.1)
U256_MAX = (1 << 256) - 1
U128_MAX = (1 << 128) - 1


def mul(a, b):
    """Every product that can exceed 128 bits. A port must use a 256-bit multiply here."""
    r = a * b
    assert abs(r) <= U256_MAX, "U256 overflow"
    return r


def subsidy(h):
    n = h // HALVING
    return 0 if n >= 64 else COIN_SUBSIDY0 >> n


def split(h):
    s = subsidy(h)
    t = s // TREASURY_DIV
    return t, s - t               # treasury base, miner pool Rm


def cut(h):
    return h - CUT_LAG


def split_slots(n):
    """(O oldest, L largest). O = ceil(N/2)."""
    o = (n + 1) // 2
    return o, n - o


def share_face(tier_log2, nbits, h):
    """Face of one share: floor(2^tier * Rm_h * T * 2^32 / (0xFFFF * 2^208)). T from the share's own header nBits,
    h = the job height. Unchanged from draft 2."""
    _, rm = split(h)
    exp, mant = nbits >> 24, nbits & 0x007FFFFF
    num = mul(rm, mant) << tier_log2
    s = 32 + 8 * (exp - 3) - 208
    r = (num << s) // 0xFFFF if s >= 0 else num // (0xFFFF << -s)
    assert (num << max(s, 0)) <= U256_MAX
    return r


def select(state, slots):
    """(oldest, largest): lists of (script, owed). largest[0] is top, the remainder absorber. state: {script: (owed, queue_since)}."""
    O, L = split_slots(slots)
    el = [(a, v) for a, v in state.items() if v[0] >= FLOOR]
    assert all(v[1] is not None for _, v in el), "eligible balance with no queue_since"
    if not el:
        return [], []
    by_size = sorted(el, key=lambda kv: (-kv[1][0], kv[0]))
    top = by_size[0]
    by_age = sorted([kv for kv in el if kv[0] != top[0]], key=lambda kv: (kv[1][1], -kv[1][0], kv[0]))
    old = by_age[:O]
    oset = {a for a, _ in old}
    big = [top] + [kv for kv in by_size[1:] if kv[0] not in oset][:L - 1]
    return [(a, v[0]) for a, v in old], [(a, v[0]) for a, v in big]


def build_outputs(h, state, slots):
    """Returns (treasury sats, [(script, sats)] in output order, [(script, retired_face)], info).
    Output order = pay order: oldest, largest without top, then top last. The rule reads nothing but its arguments."""
    tre, rm = split(h)
    old, big = select(state, slots)
    left = rm
    outs = []
    for a, owed in old + big[1:]:
        if left < MIN_PAY:
            break
        p = min(owed // ONE, left)
        left -= p
        outs.append((a, p))
    paid_top = 0
    if big:
        p = min(big[0][1] // ONE, left)
        if p >= MIN_PAY:
            left -= p
            outs.append((big[0][0], p))
            paid_top = p
    retired = [(a, p * ONE) for a, p in outs]
    info = dict(change=left, n_oldest=len(old), n_largest=len(big), paid_oldest=min(len(outs), len(old)), paid_top=paid_top,
                top_partial=bool(big) and 0 < paid_top < big[0][1] // ONE)
    return tre + left, outs, retired, info


def select_draft8(state, slots):
    """Draft 3.0 rule (no absorber), kept for reference. (oldest, largest): lists of (script, owed) in pay order. state: {script: (owed, queue_since)}."""
    O, L = split_slots(slots)
    el = [(a, v) for a, v in state.items() if v[0] >= FLOOR]
    assert all(v[1] is not None for _, v in el), "eligible balance with no queue_since"
    by_age = sorted(el, key=lambda kv: (kv[1][1], -kv[1][0], kv[0]))
    old = by_age[:O]
    oset = {a for a, _ in old}
    rest = sorted((kv for kv in el if kv[0] not in oset), key=lambda kv: (-kv[1][0], kv[0]))
    big = rest[:L]
    return [(a, v[0]) for a, v in old], [(a, v[0]) for a, v in big]


def build_outputs_draft8(h, state, slots):
    """Draft 3.0 rule (no absorber). Returns (treasury sats, [(script, sats)] in pay order, [(script, retired_face)], info).
    The rule reads nothing but its arguments."""
    tre, rm = split(h)
    old, big = select_draft8(state, slots)
    left = rm
    outs = []
    for a, owed in old + big:
        if left < MIN_PAY:
            break
        p = min(owed // ONE, left)
        left -= p
        outs.append((a, p))
    retired = [(a, p * ONE) for a, p in outs]
    info = dict(change=left, n_oldest=len(old), n_largest=len(big), paid_oldest=min(len(outs), len(old)))
    return tre + left, outs, retired, info


def apply_credits(state, deltas, c):
    """Add a batch of credits of share height c (visible from table height c + 20). In place. Returns an undo list."""
    undo = []
    for a in sorted(deltas):
        v = state.get(a)
        undo.append((a, v))
        o, q = v if v is not None else (0, None)
        o += deltas[a]
        if q is None and o >= FLOOR:
            q = c
        elif q is not None and o < FLOOR:       # a negative credit (never produced by shares) would clear too
            q = None
        state[a] = (o, q)
    return undo


def apply_block(state, retired):
    """Apply retirements. In place. Returns an undo list. Only a balance falling below FLOOR clears queue_since."""
    undo = []
    for a, r in retired:
        v = state.get(a)                  # absent only when the block's table came from another fork
        undo.append((a, v))
        o, q = v if v is not None else (0, None)
        o -= r
        state[a] = (o, None if o < FLOOR else q)
    return undo


def revert(state, undo):
    """Exact inverse of apply_credits/apply_block, for reorgs."""
    for a, v in reversed(undo):
        if v is None:
            del state[a]
        else:
            state[a] = v


def table_for(H, credits, blocks, start=None):
    """The table block H is built on: credits of share height <= cut(H), retirements of blocks at heights < H.
    credits: {share_height: {script: face}}, blocks: {height: [(script, retired_face)]} (one chain).
    Fold order, per table height P ascending: credits of share height P - 20 (pinned at P), then block P if P < H."""
    s = {}
    keys = set(c + CUT_LAG for c in credits) | set(blocks)
    for P in sorted(k for k in keys if k <= H):
        if P - CUT_LAG in credits:
            apply_credits(s, credits[P - CUT_LAG], P - CUT_LAG)
        if P < H and P in blocks:
            apply_block(s, blocks[P])
    return s


def table_root(state):
    """Canonical digest. owed is signed in 32 bytes two's complement, because a retirement computed on another
    fork's table can exceed this fork's owed."""
    m = hashlib.sha256()
    for a in sorted(state):
        o, q = state[a]
        m.update(len(a).to_bytes(2, "big") + a + (o & U256_MAX).to_bytes(32, "big")
                 + (q if q is not None else 0xFFFFFFFF).to_bytes(4, "big"))
    return m.digest()


def script_ok(s):
    """P2SH, P2WPKH, P2WSH, P2TR only (P2PKH excluded, spec 2.1)."""
    return ((len(s) == 23 and s[:2] == b"\xa9\x14" and s[22:] == b"\x87")
            or (len(s) == 22 and s[:2] == b"\x00\x14")
            or (len(s) == 34 and s[:2] == b"\x00\x20")
            or (len(s) == 34 and s[:2] == b"\x51\x20"))


def p2tr(tag):
    return b"\x51\x20" + hashlib.sha256(tag if isinstance(tag, bytes) else str(tag).encode()).digest()


def p2wpkh(tag):
    return b"\x00\x14" + hashlib.sha256(tag if isinstance(tag, bytes) else str(tag).encode()).digest()[:20]


TREASURY_SCRIPT = p2tr(b"placeholder treasury, compiled constant, see plan section 5")


def commitment_script(root):
    return b"\x6a\x24" + b"GHNP" + root


def witness_script(wtxid_commitment):
    return b"\x6a\x24\xaa\x21\xa9\xed" + wtxid_commitment


def coinbase_outputs(h, state, slots, finder_script, finder_value, witness_commitment=b"\x00" * 32):
    """Fixed layout: treasury, miners in pay order, finder, commitment OP_RETURN, witness commitment.
    A zero-value finder output is omitted. Finder is positional and retires nothing."""
    tre, outs, retired, info = build_outputs(h, state, slots)
    o = [(tre, TREASURY_SCRIPT)] + [(p, a) for a, p in outs]
    if finder_value > 0:
        o.append((finder_value, finder_script))
    o.append((0, commitment_script(table_root(state))))
    o.append((0, witness_script(witness_commitment)))
    return o, retired


def varint_len(n):
    return 1 if n < 0xfd else 3 if n <= 0xffff else 5


def outputs_bytes(o):
    return varint_len(len(o)) + sum(8 + varint_len(len(s)) + len(s) for _, s in o)


def outputs_digest(o):
    m = hashlib.sha256()
    for v, s in o:
        m.update(v.to_bytes(8, "little") + bytes([len(s)]) + s)
    return m.hexdigest()


def check_invariants(h, state, res, slots):
    tre, outs, retired, info = res
    t, rm = split(h)
    S = t + rm
    paid = sum(p for _, p in outs)
    assert tre + paid == S, "treasury + miners != subsidy"
    assert tre == t + (rm - paid) and tre >= t
    assert len(outs) <= slots and len({a for a, _ in outs}) == len(outs)
    assert all(p >= MIN_PAY for _, p in outs), "an output below 1,000 sats"
    assert all(p * ONE <= state[a][0] for a, p in outs), "paid more than owed"
    assert retired == [(a, p * ONE) for a, p in outs], "retired != pay"
    full = [p == state[a][0] // ONE for a, p in outs]
    assert all(full[:-1]), "a partial payee that is not last"
    old, big = select(state, slots)
    sel = old + big[1:]
    top_paid = bool(outs) and bool(big) and outs[-1][0] == big[0][0]
    rest = outs[:-1] if top_paid else outs
    assert [a for a, _ in rest] == [a for a, _ in sel[:len(rest)]], "not in pay order"
    if len(rest) < len(sel) or (big and not top_paid):
        assert rm - paid < MIN_PAY, "stopped with >= 1,000 sats left and payees waiting"
    if big and len(rest) == len(sel) and not top_paid:
        assert rm - sum(p for _, p in rest) < MIN_PAY, "top unpaid with >= 1,000 sats left"
    if info["change"] >= MIN_PAY:
        assert all(full) and len(outs) == len(old) + len(big), "change >= 1,000 sats while someone selected is unpaid"
    # top is the largest; oldest really are the oldest of the rest, largest really are the largest of what remains
    el = {a: v for a, v in state.items() if v[0] >= FLOOR}
    if el:
        assert big[0][0] == min(el, key=lambda a: (-el[a][0], a)), "top is not the largest eligible"
        el.pop(big[0][0])
    O, L = split_slots(slots)
    assert len(old) == min(O, len(el)) and len(big) - 1 == min(L - 1, len(el) - len(old)) if big else not old
    if old and len(el) > len(old):
        worst = max((state[a][1], -state[a][0], a) for a, _ in old)
        assert all((v[1], -v[0], a) > worst for a, v in el.items() if a not in {x for x, _ in old})


# --- portable generators -------------------------------------------------------------------------------------

def gen(seed, n, q0=900_000):
    """Portable table: row i has script p2tr(f"{seed}/{i}"); b = sha256(f"g{seed}/{i}");
    e = b[0] % 8; if e == 0 the row is below the floor: owed = int(b[1:9]) % FLOOR, queue_since None;
    else owed = (1000 + int(b[1:9]) % (1000 << 2e)) * 2^32 + int(b[9:13]), queue_since = q0 + int(b[13:15]) % 5000.
    int() is big-endian unsigned. Rows at e >= 1 are 1,000 sats to 16.4M sats."""
    s = {}
    for i in range(n):
        b = hashlib.sha256(f"g{seed}/{i}".encode()).digest()
        e = b[0] % 8
        if e == 0:
            s[p2tr(f"{seed}/{i}")] = (int.from_bytes(b[1:9], "big") % FLOOR, None)
        else:
            sat = 1000 + int.from_bytes(b[1:9], "big") % (1000 << (2 * e))
            s[p2tr(f"{seed}/{i}")] = (sat * ONE + int.from_bytes(b[9:13], "big"), q0 + int.from_bytes(b[13:15], "big") % 5000)
    return s


def flat(n, sats, tag="flat"):
    """n equal balances of `sats`, queue_since 900,000 + i // 450, scripts p2tr(f"{tag}{i}")."""
    return {p2tr(f"{tag}{i}"): (sats * ONE, 900_000 + i // 450) for i in range(n)}


def st(*rows):
    """state from (tag, owed_face, queue_since). queue_since forced to None when owed is below the floor."""
    return {p2tr(t): (o, (q if o >= FLOOR else None)) for t, o, q in rows}


def vector(name, h, state, slots=500, extra=None, gen_desc=None):
    res = build_outputs(h, state, slots)
    check_invariants(h, state, res, slots)
    tre, outs, ret, info = res
    d = hashlib.sha256(json.dumps([tre, [(a.hex(), p) for a, p in outs], [(a.hex(), str(r)) for a, r in ret]]).encode()).hexdigest()
    v = dict(name=name, height=h, slots=slots, n_input=len(state), treasury=tre, change=info["change"],
             n_miner_outputs=len(outs), n_oldest_selected=info["n_oldest"], n_largest_selected=info["n_largest"],
             miner_total=sum(p for _, p in outs), table_root=table_root(state).hex(), digest=d)
    if len(outs) <= 12:
        v["outputs"] = [(a.hex(), p) for a, p in outs]
    else:
        v["first_outputs"] = [(a.hex(), p) for a, p in outs[:3]]
        v["last_output"] = [(a.hex(), p) for a, p in outs[-1:]]
    if len(state) <= 64:
        v["input"] = {a.hex(): [str(s[0]), s[1]] for a, s in state.items()}
    else:
        v["input"] = gen_desc or "generated"
    if extra:
        v.update(extra)
    return v


def replay_equivalence(seed, n_addr=300, steps=400):
    """Random credits, blocks and reorgs. A node holding one state with undo logs must always equal a fold of the
    surviving history, including queue_since; and every block obeys check_invariants."""
    r = random.Random(seed)
    addrs = [p2tr(f"r{seed}/{i}") for i in range(n_addr)]
    live, hist, undos = {}, [], []
    h = 974_500
    reorgs = 0
    for step in range(steps):
        c = r.random()
        if c < 0.08 and undos:
            d = r.randint(1, min(3, len(undos)))
            for _ in range(d):
                revert(live, undos.pop())
                hist.pop()
            reorgs += 1
        elif c < 0.45:
            b = {a: r.randrange(1, 4_000_000) * ONE // 1000 for a in r.sample(addrs, r.randint(1, 80))}
            undos.append(apply_credits(live, b, h))
            hist.append(("c", b, h))
        elif live:
            sl = r.choice(list(SLOT_CLASSES.values()))
            res = build_outputs(h, live, sl)
            check_invariants(h, live, res, sl)
            undos.append(apply_block(live, res[2]))
            hist.append(("b", res[2], h))
        h += 1
        if step % 25 == 0:
            s = {}
            for k, a, hh in hist:
                apply_credits(s, a, hh) if k == "c" else apply_block(s, a)
            assert s == live and table_root(s) == table_root(live), "undo path differs from fold"
            assert all(q is None or o >= FLOOR for o, q in live.values())
            assert all(q is not None for o, q in live.values() if o >= FLOOR)
            assert min((o for o, _ in live.values()), default=0) >= 0, "negative balance on one chain"
    return reorgs


def main():
    H = 974_500
    NB = 0x1702_1B00 | 0x0000_0E5
    t0, RM = split(H)
    V = []
    assert (t0, RM) == (1_562_500, 310_937_500)
    assert split(1_050_000) == (781_250, 155_468_750)
    assert [split_slots(n) for n in SLOT_CLASSES.values()] == [(2, 1), (5, 4), (22, 22), (72, 71), (182, 182), (250, 250)]
    assert cut(H) == H - 20

    # share_face goldens, unchanged from draft 1/2
    f10 = share_face(10, NB, H)
    assert f10 == 10246338 and share_face(40, NB, H) == 11001922676017395
    assert share_face(10, NB, 1_049_999) == 2 * share_face(10, NB, 1_050_000)
    fv = dict(name="share_face", tier=10, nbits=hex(NB), height=H, face=str(f10), tier40=str(share_face(40, NB, H)),
              after_halving=str(share_face(10, NB, 1_050_000)), before_halving=str(share_face(10, NB, 1_049_999)))

    # --- degenerate tables -------------------------------------------------------------------------------
    V.append(vector("empty table: whole subsidy to treasury", H, {}))
    V.append(vector("all below floor or non-positive: whole subsidy to treasury", H,
                    st(("a", -5, None), ("b", 0, None), ("c", FLOOR - 1, None))))
    res = build_outputs(H, st(("c", FLOOR - 1, None)), 500)
    assert res[0] == subsidy(H) and res[1] == []

    # --- launch: little owed, change to treasury ------------------------------------------------------------
    launch = st(("big1", 40_000_000 * ONE + 77, H - 30), ("big2", 25_000_000 * ONE, H - 25), ("mid", 3_000_000 * ONE + 5, H - 22),
                ("bitaxe1", 1_000 * ONE, H - 21), ("bitaxe2", 600 * ONE, None), ("bitaxe3", 999 * ONE + ONE - 1, None))
    res = build_outputs(H, launch, 500)
    check_invariants(H, launch, res, 500)
    assert res[3]["change"] == RM - (40_000_000 + 25_000_000 + 3_000_000 + 1_000) and len(res[1]) == 4
    assert res[0] == t0 + res[3]["change"]
    V.append(vector("launch: four eligible balances, 68.0M owed of 310.9M, change to treasury", H, launch, 500))
    V.append(vector("launch: same table on a class-3 block, the 3 selected are paid in full", H, launch, 3))
    one = st(("first", 1_234 * ONE + 999, H - 21))
    res = build_outputs(H, one, 500)
    assert res[1] == [(p2tr("first"), 1_234)] and res[0] == subsidy(H) - 1_234
    V.append(vector("launch: one balance of 1,234.0000002 sats", H, one, 500))

    # --- exact floor boundary ------------------------------------------------------------------------------
    b = st(("at", FLOOR, 10), ("below", FLOOR - 1, None))
    res = build_outputs(H, b, 9)
    assert res[1] == [(p2tr("at"), 1000)]
    V.append(vector("floor boundary: owed == 1,000 sats paid, one face unit less is not eligible", H, b, 9))
    q = {}
    apply_credits(q, {p2tr("x"): FLOOR - 1}, 10)
    assert q[p2tr("x")] == (FLOOR - 1, None)
    apply_credits(q, {p2tr("x"): 1}, 11)
    assert q[p2tr("x")] == (FLOOR, 11)

    # --- per-class plain cases -------------------------------------------------------------------------------
    for sl in SLOT_CLASSES.values():
        V.append(vector(f"class {sl}: 900 mixed balances", H, gen(7, 900), sl, gen_desc="gen(7, 900)"))
    fl = flat(23_000, 18_000)
    for sl in (9, 500):
        res = build_outputs(H, fl, sl)
        assert res[3]["change"] == RM - 18_000 * sl
        V.append(vector(f"class {sl}: 23,000 flat 18,000-sat balances, change to treasury", H, fl, sl, gen_desc="flat(23000, 18000)"))

    # --- a 9-output block ---------------------------------------------------------------------------------------
    nine = st(*[(f"o{i}", (2_000 + i) * ONE, 100 + i) for i in range(8)],
              *[(f"w{i}", (50_000_000 + i * 1_000) * ONE, 500) for i in range(6)])
    res = build_outputs(H, nine, 9)
    names = {p2tr(f"o{i}"): f"o{i}" for i in range(8)} | {p2tr(f"w{i}"): f"w{i}" for i in range(6)}
    assert [names[a] for a, _ in res[1]] == ["o0", "o1", "o2", "o3", "o4", "w4", "w3", "w2", "w5"][:len(res[1])]
    # 5 oldest take 10,010 sats, then w5 50.005M, w4 50.004M, w3 50.003M, w2 50.002M = 200.014M; all fit
    assert len(res[1]) == 9 and res[3]["change"] == RM - (2_000 * 5 + 10) - (4 * 50_000_000 + 14_000)
    assert res[1][-1] == (p2tr("w5"), 50_005_000) and not res[3]["top_partial"]
    V.append(vector("class 9: 5 oldest then 4 largest, all paid in full (top w5 last), change to treasury", H, nine, 9))

    # --- Rm runs out mid-list ---------------------------------------------------------------------------------
    mid = st(*[(f"q{i}", 100_000_000 * ONE + i, 10 + i) for i in range(5)], *[(f"l{i}", 900_000_000 * ONE, 50) for i in range(4)])
    res = build_outputs(H, mid, 9)
    # q0..q2 take 300,000,000; q3 takes the remaining 10,937,500; q4 and every largest get nothing
    assert [p for _, p in res[1]] == [100_000_000] * 3 + [10_937_500] and res[3]["change"] == 0
    after = dict(mid)
    apply_block(after, res[2])
    assert after[p2tr("q3")] == (mid[p2tr("q3")][0] - 10_937_500 * ONE, 13), "a partial payment keeps its place"
    assert after[p2tr("q0")] == (0, None)
    V.append(vector("Rm runs out inside the oldest list: 4th oldest paid in part, no largest paid", H, mid, 9))
    mid2 = st(*[(f"q{i}", 1_000_000 * ONE, 10 + i) for i in range(5)], *[(f"l{i}", (200_000_000 - i) * ONE, 50) for i in range(4)])
    res = build_outputs(H, mid2, 9)
    # top is l0 (200,000,000); l1 is paid in full, l2 in part, l3 and top get nothing
    assert [p for _, p in res[1]] == [1_000_000] * 5 + [199_999_999, RM - 5_000_000 - 199_999_999]
    assert p2tr("l0") not in dict(res[1]) and res[3]["change"] == 0
    V.append(vector("Rm runs out inside the largest list before top: 3rd largest paid in part, top waits", H, mid2, 9))
    absorb = st(*[(f"q{i}", 1_000_000 * ONE, 10 + i) for i in range(5)], *[(f"l{i}", 10_000_000 * ONE, 50) for i in range(1, 4)],
                ("l0", 500_000_000 * ONE + 3, 60))
    res = build_outputs(H, absorb, 9)
    assert res[1][:8] == [(p2tr(f"q{i}"), 1_000_000) for i in range(5)] + sorted([(p2tr(f"l{i}"), 10_000_000) for i in range(1, 4)])
    assert res[1][-1] == (p2tr("l0"), RM - 35_000_000) and res[3]["top_partial"] and res[3]["change"] == 0
    V.append(vector("top absorbs: all others paid in full, top (largest) paid the remainder in part, last output", H, absorb, 9))
    full = st(*[(f"q{i}", 1_000_000 * ONE, 10 + i) for i in range(5)], *[(f"l{i}", 10_000_000 * ONE, 50) for i in range(1, 4)],
              ("l0", 50_000_000 * ONE + 3, 60))
    res = build_outputs(H, full, 9)
    assert res[1][-1] == (p2tr("l0"), 50_000_000) and not res[3]["top_partial"] and res[3]["change"] == RM - 85_000_000
    assert res[0] == t0 + RM - 85_000_000
    V.append(vector("all 9 slots paid in full including top, change to treasury", H, full, 9))

    # stop rule: left exactly 1,000 pays the next (at most 1,000); left 999 stops and 999 goes to the treasury
    s1000 = st(("a", (RM - 1_000) * ONE, 1), ("b", 5_000 * ONE, 2), ("c", 900_000_000 * ONE, 3))     # c is top
    res = build_outputs(H, s1000, 9)
    assert res[1] == [(p2tr("a"), RM - 1_000), (p2tr("b"), 1_000)] and res[3]["change"] == 0
    V.append(vector("stop rule: 1,000 sats left still pays the next payee 1,000", H, s1000, 9))
    s999 = st(("a", (RM - 999) * ONE, 1), ("b", 5_000 * ONE, 2), ("c", 900_000_000 * ONE, 3))
    res = build_outputs(H, s999, 9)
    assert res[1] == [(p2tr("a"), RM - 999)] and res[3]["change"] == 999 and res[0] == t0 + 999
    V.append(vector("stop rule: 999 sats left stops, 999 to treasury, payee b and top c wait", H, s999, 9))

    # --- ties --------------------------------------------------------------------------------------------------------
    tie = st(*[(c, 5_000 * ONE, 7) for c in "zyxwvu"], ("bigger", 6_000 * ONE, 7), ("older", 1_500 * ONE, 6))
    res = build_outputs(H, tie, 3)
    old, big = select(tie, 3)
    by = sorted([p2tr(c) for c in "zyxwvu"])
    assert [a for a, _ in old] == [p2tr("older"), by[0]] and [a for a, _ in big] == [p2tr("bigger")], "bigger is top, reserved"
    V.append(vector("ties: queue_since, then owed desc, then script asc (class 3)", H, tie, 3))
    tie2 = st(*[(c, 5_000 * ONE, i) for i, c in enumerate("abcd")], *[(c, 9_000 * ONE, 99) for c in "zyxwvu"])
    old, big = select(tie2, 9)
    six = sorted(p2tr(c) for c in "zyxwvu")
    assert [a for a, _ in old] == [p2tr(c) for c in "abcd"] + six[1:2] and [a for a, _ in big] == six[:1] + six[2:5], "six[0] is top by script"
    V.append(vector("ties: equal largest broken by script bytes", H, tie2, 9))

    # --- sub-sat remainder ---------------------------------------------------------------------------------------------
    frac = st(("f", 7_777 * ONE + ONE - 1, 3))
    res = build_outputs(H, frac, 9)
    apply_block(frac, res[2])
    assert res[1] == [(p2tr("f"), 7_777)] and frac[p2tr("f")] == (ONE - 1, None), "remainder stays owed, queue clears"

    # --- 500-output block and the 503/504-output goldens ------------------------------------------------------------
    V.append(vector("class 500: 600 mixed balances", H, gen(5, 600), 500, gen_desc="gen(5, 600)"))
    for fv_name, script_fn, nm in (("P2TR", p2tr, "t"), ("P2WPKH", p2wpkh, "w")):
        s = {script_fn(f"g{nm}{i}"): ((5000 + i) * ONE, 900_000 + i // 450) for i in range(400)}
        s.update({script_fn(f"top{nm}{i}"): ((600_000 + i) * ONE, 900_100) for i in range(300)})
        for finder_value, want in ((123_456, 504), (0, 503)):
            o, ret = coinbase_outputs(H, s, 500, script_fn("finder"), finder_value)
            assert len(o) == want, (len(o), want)
            assert sum(v for v, _ in o) == subsidy(H) + finder_value
            assert all(script_ok(sc) for _, sc in o[:want - 2])
            V.append(vector(f"{want} outputs, {fv_name}, finder {finder_value}", H, s, 500,
                            dict(coinbase_outputs=want, output_section_bytes=outputs_bytes(o), output_digest=outputs_digest(o)),
                            gen_desc=f"400 x ({script_fn.__name__}('g{nm}'+i), (5000+i) sats, 900000+i//450) + 300 x ({script_fn.__name__}('top{nm}'+i), (600000+i) sats, 900100)"))
    # fee differences change only the finder value and the witness commitment
    s = {p2tr(f"fee{i}"): ((5000 + i) * ONE, 900_000) for i in range(400)}
    s.update({p2tr(f"feetop{i}"): ((600_000 + i) * ONE, 900_100) for i in range(300)})
    a, _ = coinbase_outputs(H, s, 500, p2tr("nodeA"), 1_000_000, b"\x01" * 32)
    b2, _ = coinbase_outputs(H, s, 500, p2tr("nodeB"), 40_000_000, b"\x02" * 32)
    assert len(a) == 504 and a[:501] == b2[:501] and a[-2] == b2[-2] and a[-3] != b2[-3] and a[-1] != b2[-1]
    # finder also holds a balance: positional, so its fee output retires nothing
    sf = {p2tr("nodeA"): (5000 * ONE, 900_000), p2tr("other"): (6000 * ONE, 900_000)}
    o, ret = coinbase_outputs(H, sf, 500, p2tr("nodeA"), 9_999)
    assert sum(1 for _, sc in o if sc == p2tr("nodeA")) == 2 and len([1 for sc, _ in ret if sc == p2tr("nodeA")]) == 1

    # --- cut(H) = H - 20 and retired through H - 1 ----------------------------------------------------------------
    cr = {H - 25: {p2tr("m"): 3_000 * ONE}, H - 20: {p2tr("n"): 2_000 * ONE}, H - 19: {p2tr("late"): 9_000 * ONE}}
    t_H = table_for(H, cr, {})
    assert set(t_H) == {p2tr("m"), p2tr("n")} and t_H[p2tr("m")][1] == H - 25, "credit at H-19 is beyond the cut"
    res_H = build_outputs(H, t_H, 9)
    blocks = {H: res_H[2]}
    t_H1 = table_for(H + 1, cr, blocks)
    assert t_H1[p2tr("late")] == (9_000 * ONE, H - 19) and t_H1[p2tr("m")] == (0, None), "block H retired before H+1"
    res_H1 = build_outputs(H + 1, t_H1, 9)
    assert res_H1[1] == [(p2tr("late"), 9_000)]
    V.append(vector("cut: block H sees credits through H-20 only", H, t_H, 9, dict(credits={str(k): {a.hex(): str(x) for a, x in d.items()} for k, d in cr.items()})))
    V.append(vector("cut: block H+1 sees block H retired and the credit at H-19", H + 1, t_H1, 9))

    # --- consecutive blocks on overlapping tables -------------------------------------------------------------------
    snap = {p2tr(f"s{i}"): ((3000 + (i * 37) % 9000) * ONE, 900_000 + i // 300) for i in range(1500)}
    snap.update({p2tr(f"sw{i}"): ((40_000_000 + i) * ONE, 900_010) for i in range(20)})
    root0 = table_root(snap)
    r1 = build_outputs(H, snap, 500); check_invariants(H, snap, r1, 500)
    s1 = dict(snap); apply_block(s1, r1[2])
    r2 = build_outputs(H + 1, s1, 143); check_invariants(H + 1, s1, r2, 143)
    rep = {a for a, _ in r1[1]} & {a for a, _ in r2[1]}
    assert all(snap[a][0] // ONE > dict(r1[1])[a] for a in rep), "a repeat payee must have been partial"
    V.append(vector("two blocks, no new credits: first", H, snap, 500, dict(snapshot_root=root0.hex()), gen_desc="see main(): snap"))
    V.append(vector("two blocks, no new credits: second, retired through H", H + 1, s1, 143, dict(snapshot_root=root0.hex()), gen_desc="snap after block 1"))

    # --- reorg restores balances, including queue_since cleared by the orphaned block -------------------------------
    pre = {p2tr(f"o{i}"): ((3000 + i) * ONE, 900_000 + i) for i in range(800)}
    root_pre, copy_pre = table_root(pre), dict(pre)
    rA = build_outputs(H, pre, 500)
    undo = apply_block(pre, rA[2])
    root_a = table_root(pre)
    assert root_a != root_pre and any(pre[a][1] is None for a, _ in rA[2])
    revert(pre, undo)
    assert pre == copy_pre and table_root(pre) == root_pre
    V.append(vector("reorg: block A undone, block B (class 44) on the restored table", H, pre, 44,
                    dict(root_before=root_pre.hex(), root_after_A=root_a.hex(), root_after_undo=table_root(pre).hex()),
                    gen_desc="800 x (p2tr('o'+i), (3000+i) sats, 900000+i)"))
    # reorg through table_for: two chains share credits, differ in blocks
    crs = {H - 30 + k: {p2tr(f"c{j}"): (2_000 + 100 * k + j) * ONE for j in range(30)} for k in range(10)}
    tA = table_for(H, crs, {}); bA = build_outputs(H, tA, 500)[2]
    tB = table_for(H, crs, {}); bB = build_outputs(H, tB, 9)[2]
    assert table_for(H + 1, crs, {H: bA}) != table_for(H + 1, crs, {H: bB})
    live = table_for(H, crs, {}); u = apply_block(live, bA); revert(live, u); apply_block(live, bB)
    t_chk = table_for(H + 1, {k: v for k, v in crs.items() if k <= H - 20}, {H: bB})     # B's chain, credits held at the cut
    assert live == t_chk and table_root(live) == table_root(t_chk), "undo of A then B differs from a fold of B's chain"

    # --- halving -----------------------------------------------------------------------------------------------------
    hv = gen(6, 600)
    V.append(vector("last block before halving", 1_049_999, hv, 500, gen_desc="gen(6, 600)"))
    V.append(vector("halving block: Rm halves, fewer payees", 1_050_000, hv, 500, gen_desc="gen(6, 600)"))
    rh = build_outputs(1_050_000, hv, 500)
    assert rh[0] + sum(p for _, p in rh[1]) == 156_250_000
    hv2 = st(("w", 200_000_000 * ONE, 5), ("x", 2_000 * ONE, 4))
    a0 = build_outputs(1_049_999, hv2, 9); a1 = build_outputs(1_050_000, hv2, 9)
    assert a0[1] == [(p2tr("x"), 2_000), (p2tr("w"), 200_000_000)] and a1[1] == [(p2tr("x"), 2_000), (p2tr("w"), 155_466_750)]
    V.append(vector("halving block: whale paid in part at the new Rm", 1_050_000, hv2, 9))

    # --- U256 and storage ceilings --------------------------------------------------------------------------------
    wmax = st(("w", 21_000_000 * 10 ** 8 * ONE, 1))
    res = build_outputs(H, wmax, 500)
    assert res[1] == [(p2tr("w"), RM)] and res[3]["change"] == 0
    V.append(vector("total supply in one script: paid Rm, partial", H, wmax, 500))
    assert 21_000_000 * 10 ** 8 * ONE > (1 << 63), "i64 cannot hold it, hence blobs"

    # --- fuzz: nobody is ever paid more than owed; order independence; multi-block replay ---------------------------
    worst_over = 0
    for seed in range(40):
        o = gen(100 + seed, 800)
        h = H
        for blk in range(25):
            sl = list(SLOT_CLASSES.values())[(seed + blk) % 6]
            res = build_outputs(h, o, sl)
            items = list(o.items()); random.Random(blk).shuffle(items)
            assert res == build_outputs(h, dict(items), sl), "order dependence"
            check_invariants(h, o, res, sl)
            worst_over = max([worst_over] + [p * ONE - o[a][0] for a, p in res[1]])
            apply_block(o, res[2])
            assert min(v[0] for v in o.values()) >= 0, "negative balance"
            h += 144
            apply_credits(o, {a: ONE * 400 for a in o}, h - CUT_LAG)
    assert worst_over <= 0
    reorgs = sum(replay_equivalence(s) for s in range(60))

    out = dict(constants=dict(SLOT_CLASSES=SLOT_CLASSES, OLDEST_LARGEST={sl: split_slots(sl) for sl in SLOT_CLASSES.values()},
                              MIN_PAY=MIN_PAY, CUT_LAG=CUT_LAG, TREASURY_DIV=TREASURY_DIV, UNIT="2^-32 sat"),
               rule="refimpl_v3.py docstring; pay in whole sats, retired = pay * 2^32",
               generators=dict(gen=gen.__doc__.strip(), flat=flat.__doc__.strip()),
               digest="sha256(json.dumps([treasury, [[script_hex, sats]...], [[script_hex, str(retired_face)]...]]))",
               share_face=fv, vectors=V)
    json.dump(out, open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_vectors_v3.json"), "w"), indent=1)
    print("ok", len(V), "vectors;", reorgs, "random reorgs replayed; 1000 fuzz blocks, worst overpay", worst_over)
    for v in V:
        if "output_section_bytes" in v:
            print(v["name"], v["output_section_bytes"], "bytes")


if __name__ == "__main__":
    main()

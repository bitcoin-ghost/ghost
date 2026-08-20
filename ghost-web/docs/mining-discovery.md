# Mining discovery without trusting DNS

Pointing a miner at `pool.bitcoinghost.org` means trusting DNS, and trusting whoever serves that
name. Ghost's answer is a **signed node list**: the pool nodes agree on a checkpoint of who serves
mining and where, sign it with a supermajority of the elder set, and publish it. A miner-side shim
fetches that checkpoint from any node, verifies it **offline** against a root of trust it already
holds, and only then connects.

Nothing in that path requires trusting DNS, this website, or the node that served the blob.

---

## Status: not yet live

**The node-list checkpoint is dormant.** `MESH_NODE_LIST_CHECKPOINT_HEIGHT` is `u64::MAX`, so no
checkpoint is proposed and none is served. The shim has nothing to verify yet.

The genesis signer set below is published now because it is **stable and independently
verifiable today** — you can check it against any pool node yourself, and it is the same value
that will anchor the chain when discovery is armed. Nothing else on this page is usable yet.

Before it can be armed, three things must be true:

1. The checkpoint must **converge** — every node must derive a byte-identical blob. It could not
   until recently: the node set was built from each node's own view of who was reachable, so eight
   nodes produced up to six different answers and nothing ever finalised. That is fixed, but the
   fix has not been proven on the live fleet.
2. The genesis signer set must be **published** — this page.
3. At least three **independently operated seeds** must exist. Today every pool node is run by one
   operator, so a shim seeded only with Ghost nodes is trusting one party for its first fetch. That
   is a real limitation and it is not solved by code.

---

## The genesis signer set

These eight node ids are the MPC elder set — the root of trust. A checkpoint is accepted only if a
supermajority (≥67%) of the **already-trusted** set signed it, and membership changes are themselves
attested by the prior set, so the shim follows the set forward from genesis without ever re-trusting
this page.

```
46141044f80c99ac01476b3c2d6cd2149f31b5f1b06ffd2dfa3d15d588c7a39b
4c8c2272ae67d76c6c4108f0e4e6dfde7ff864689d3e9b99a35ab1bd46051132
5867b555602257bdffa5d4c3577c464416087f2aa04ac478f3986a17e51d3393
849bceceb22cc7ebbeec252d824940ebb73ee08c7855c5a90b5661dd21aeb18c
9fe860bda96ff81820a2e166f48cb3ae59010fc9e42550a3aeafb5bfef4d1b38
e557c97a32335457ed6eceb6f8a9c7ee13f8731ee99dc9f4b7831dcf606d6927
f0215f1ffd9a711ffc8e476f37bf3e19a2afc18803d146ecedb5d53d4fe9bd4f
fb71fee87bb0516920fdb673f3068be3c0b9b29fc62e309b99594a0008c25622
```

Sorted and concatenated, `sha256` of that set is:

```
06d1d5a1cd930c33a978694910c862637be54689005b762bfa3c0b28d7cbfeda
```

**Do not take this list on faith — check it.** Every node serves its own view:

```sh
curl -sk https://<any-pool-node>:8443/api/v1/network/elder \
  | jq -r '.elders[].node_id' | sort
```

Verified against all eight nodes on 2026-08-20: identical, 8 elders, same hash. If a node disagrees
with this page, trust the nodes and tell us — a set this page gets wrong is a wrong root of trust,
which is worse than no page at all.

---

## Why a published list is still weaker than a compiled-in one

Taking the set from this page means trusting this page **at that moment**. After the first fetch you
are on the signed chain and the website cannot lie to you again — but the first fetch is
trust-on-faith.

The stronger option is to compile the set into your own build of the shim, from a source you
already trust (the repository, a release you verified, or a set you collected from the nodes
yourself). The shim takes it either way:

```sh
ghost-miner-proxy --seed <node-host> --genesis-file ./genesis-signers.txt
# or
ghost-miner-proxy --seed <node-host> --genesis-signers <id>,<id>,...
```

`--genesis-file` takes one hex node id per line; `#` comments are allowed.

---

## What the shim checks

For each checkpoint it fetches, before using any address in it:

1. The node list matches its declared root.
2. The proposer is in the trusted set, and its signature over the checkpoint hash verifies.
3. At least 67% of the **prior** trusted set signed an approve-vote over that hash — so an attacker
   cannot introduce their own signers and self-certify.
4. Applying the signed membership delta yields a set matching the signed signer-set root.
5. **Every advertised endpoint is signed by the node it points at**, and the rendered list is exactly
   what those adverts derive to.

Point 5 is the one worth understanding. Without it, a quorum signature says only that 67% agreed on
*a list* — not that any listed node ever claimed that address. A proposer able to reach quorum could
have pointed miners anywhere. Each node signs its own endpoint, so redirecting a node's traffic
requires that node's own key.

On any failure the shim keeps the last list it verified, rather than falling back to something
unverified.

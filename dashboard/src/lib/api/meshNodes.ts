// Mesh-nodes API client.
//
// `/api/v1/pool/mesh-nodes` is a public, no-auth endpoint that returns self +
// every connected peer with its REAL public `address` ("ip:port"), unlike
// `/api/v1/network/peers` whose `address` field is empty. This is the live
// mesh-node list the Capacity and Geo pages are built from.

import { fetchApi } from "./client";

export interface MeshNodeCapabilities {
  archive: boolean;
  ghost_pay: boolean;
  public_mining: boolean;
  reaper: boolean;
  elder: boolean;
}

export interface MeshNode {
  node_id: string;
  address: string;
  elder: boolean;
  capabilities: MeshNodeCapabilities;
  hashrate_th: number;
  // Raw connection count — a load-balancer routing view that double-counts a
  // miner failing over between nodes. Kept for reference; NOT summed.
  miner_count: number;
  // Deduplicated share of the mesh-wide active-miner total attributed to this
  // node. Each unique miner is owned by exactly one node, so summing this
  // across the list equals the deduped `mesh_active_miners` grand total the
  // Watchdog reports.
  deduped_miner_count: number;
  // Hardware-derived capacity ceiling. 0 / absent = the node has not gossiped
  // one yet (shown as "unknown", not a real ceiling).
  max_capacity?: number;
  healthy: boolean;
  is_self: boolean;
}

export interface MeshNodesResponse {
  nodes: MeshNode[];
  total: number;
}

export async function fetchMeshNodes(): Promise<MeshNodesResponse> {
  // Route through the proxy (fetchApi). Returns self + every connected peer, so
  // callers reflect the whole mesh without a hard-coded node list.
  return fetchApi<MeshNodesResponse>("/api/v1/pool/mesh-nodes");
}

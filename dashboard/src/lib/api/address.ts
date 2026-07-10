// Address-index API — trusted-mode wallet/explorer serving.
//
// These endpoints are backed by ghostd's address index (-addressindex), which
// is built from structural block data only, so they answer balance, history and
// UTXO queries on pruned and hazed nodes. Every call resolves: when the index is
// disabled or the input is invalid the backend returns `{ available: false,
// reason }` rather than throwing.
import { fetchApi } from './client';

export interface AddressUtxo {
  txid: string;
  outputIndex: number;
  height: number;
  satoshis: number;
  /** Present on descriptor scans: which derived address owns the output. */
  address?: string;
}

export interface AddressInfoOk {
  available: true;
  address: string;
  balance: number | null;
  received: number | null;
  utxos: AddressUtxo[];
  txids: string[];
}

export interface AddressUnavailable {
  available: false;
  reason: string;
}

export type AddressInfo = AddressInfoOk | AddressUnavailable;

export interface DescriptorScanOk {
  available: true;
  /** How many scripts were derived from the descriptor. */
  scanned: number;
  /** How many derived addresses had any activity (a gap-limit signal). */
  used: number;
  balance: number;
  received: number;
  utxos: AddressUtxo[];
  txids: string[];
}

export type DescriptorScan = DescriptorScanOk | AddressUnavailable;

/** Look up a single address: balance, total received, UTXOs and txids. */
export async function getAddressInfo(address: string): Promise<AddressInfo> {
  return fetchApi<AddressInfo>(`/api/v1/address/${encodeURIComponent(address.trim())}`);
}

/**
 * Scan a descriptor / xpub against the address index, aggregating balance,
 * UTXOs and history across every derived address. `range` is an optional gap
 * limit — a single number (0..N) or an explicit `[begin, end]`.
 */
export async function scanDescriptor(
  descriptor: string,
  range?: number | [number, number],
): Promise<DescriptorScan> {
  return fetchApi<DescriptorScan>('/api/v1/address/scan', {
    method: 'POST',
    body: JSON.stringify({ descriptor: descriptor.trim(), range }),
  });
}

// Haze API endpoints
import { fetchApi } from './client';
import type { HazeStatus, LegalPacket, CheckpointStatus } from '@/types/api';

export async function getHazeStatus(): Promise<HazeStatus> {
  return fetchApi<HazeStatus>('/api/v1/haze/status');
}

/**
 * Fetch the Legal Compliance Packet. Always resolves: on a non-hazed node the
 * backend returns `{ available: false, reason }` rather than erroring.
 */
export async function getLegalPacket(): Promise<LegalPacket> {
  return fetchApi<LegalPacket>('/api/v1/haze/legal-pack');
}

/** Fetch the signed-checkpoint status (the hazed node's trust anchor). */
export async function getCheckpointStatus(): Promise<CheckpointStatus> {
  return fetchApi<CheckpointStatus>('/api/v1/haze/checkpoint');
}

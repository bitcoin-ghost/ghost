// Logs API endpoints
import { fetchApi } from './client';
import type { LogsResponse, LogUnitsResponse } from '@/types/api';

export async function getLogs(
  limit?: number,
  level?: string,
  unit?: string,
): Promise<LogsResponse> {
  const params = new URLSearchParams();
  if (limit) params.set('limit', limit.toString());
  if (level) params.set('level', level);
  if (unit) params.set('unit', unit);
  const query = params.toString();
  return fetchApi<LogsResponse>(`/api/v1/logs${query ? `?${query}` : ''}`);
}

export async function getLogUnits(): Promise<LogUnitsResponse> {
  return fetchApi<LogUnitsResponse>('/api/v1/logs/units');
}

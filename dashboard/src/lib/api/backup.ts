// Backup/Migration API endpoints
import { fetchApi, fetchWithTimeout, getApiBase } from './client';
import type { BackupResponse, BackupHistoryResponse, VerifyBackupResponse, ImportBackupResponse } from '@/types/api';

// The artifact is a full snapshot of the pool database, produced server-side by
// VACUUM INTO and encrypted with the NODE's own key (payout addresses stay
// field-encrypted; a SQLCipher DB copies under the same key). There is no
// per-request password to supply — the node key is used automatically.
export async function createBackup(): Promise<BackupResponse> {
  return fetchApi<BackupResponse>('/api/v1/backup/export', {
    method: 'POST',
    body: JSON.stringify({}),
  });
}

export async function verifyBackup(file: File): Promise<VerifyBackupResponse> {
  // Read file and convert to base64 (text-safe transport through the proxy).
  const fileContent = await fileToBase64(file);

  return fetchApi<VerifyBackupResponse>('/api/v1/backup/verify', {
    method: 'POST',
    body: JSON.stringify({ file_content: fileContent }),
  });
}

export async function importBackup(file: File): Promise<ImportBackupResponse> {
  // Read file and convert to base64
  const fileContent = await fileToBase64(file);

  const response = await fetchWithTimeout(
    `${getApiBase()}/api/proxy/api/v1/backup/import`,
    {
      method: 'POST',
      body: JSON.stringify({ file_content: fileContent }),
      headers: {
        'Content-Type': 'application/json',
      },
    },
    120000 // 2 minute timeout: import verifies the artifact server-side
  );

  const data = (await response.json().catch(() => ({}))) as ImportBackupResponse;
  if (!response.ok || data.success === false) {
    throw new Error(data.error || `API error: ${response.status}`);
  }
  return data;
}

// Helper to convert File to base64
async function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result as string;
      // Remove the data URL prefix (e.g., "data:application/json;base64,")
      const base64 = result.includes(',') ? result.split(',')[1] : result;
      resolve(base64);
    };
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

export async function getBackupHistory(): Promise<BackupHistoryResponse> {
  return fetchApi<BackupHistoryResponse>('/api/v1/backup/history');
}

export async function deleteBackup(filename: string): Promise<{ success: boolean; error?: string }> {
  return fetchApi<{ success: boolean; error?: string }>(`/api/v1/backup/delete/${encodeURIComponent(filename)}`, {
    method: 'DELETE',
  });
}

export function getBackupDownloadUrl(filename: string): string {
  // Route through the HMAC-signing proxy; the proxy streams binary payloads
  // (see api/proxy/[...path]) so the download arrives byte-for-byte.
  return `${getApiBase()}/api/proxy/api/v1/backup/download/${encodeURIComponent(filename)}`;
}

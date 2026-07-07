'use client';

import { useEffect, useState } from 'react';
import { Dialog } from '@/components/ui/Dialog';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { useToast } from '@/components/ui/Toast';
import { getGhostId } from '@/lib/api/ghostpay';

interface GhostIdWizardProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function GhostIdWizard({ isOpen, onClose }: GhostIdWizardProps) {
  const toast = useToast();

  const [ghostId, setGhostId] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [prevOpen, setPrevOpen] = useState(false);

  // Reset the transient UI state the moment the dialog opens, during render
  // (guarded on the open transition so it can't loop) rather than in the effect.
  // This is React's recommended alternative to a setState-in-effect for derived
  // resets; the effect below is left to do only the async fetch.
  if (isOpen !== prevOpen) {
    setPrevOpen(isOpen);
    if (isOpen) {
      setIsLoading(true);
      setError(null);
      setCopied(false);
    }
  }

  useEffect(() => {
    if (!isOpen) return;

    let cancelled = false;

    getGhostId()
      .then((result) => {
        if (cancelled) return;
        const id = result.ghost_id?.trim();
        if (!id) {
          setError('The node did not return a Ghost ID.');
          setGhostId(null);
        } else {
          setGhostId(id);
        }
      })
      .catch((err) => {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : 'Unable to retrieve the node Ghost ID.');
        setGhostId(null);
      })
      .finally(() => {
        if (!cancelled) setIsLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [isOpen]);

  const handleCopy = async () => {
    if (!ghostId) return;
    try {
      await navigator.clipboard.writeText(ghostId);
      setCopied(true);
      toast.success('Copied', 'Ghost ID copied to clipboard.');
      setTimeout(() => setCopied(false), 2000);
    } catch {
      toast.error('Copy Failed', 'Could not copy the Ghost ID to the clipboard.');
    }
  };

  return (
    <Dialog
      isOpen={isOpen}
      onClose={onClose}
      title="Ghost ID"
      description="The node's L2 receive address, derived from its node keypair."
      size="md"
      footer={
        <Button variant="ghost" onClick={onClose}>
          Close
        </Button>
      }
    >
      <div className="space-y-4">
        <div className="p-4 rounded-lg bg-[var(--surface)]/50">
          <p className="text-sm text-[color:var(--dim)]">
            This is the single Ghost ID derived from this node&apos;s keypair. Other Ghost users
            can send L2 payments to it. It is read-only here -- L2 actions live in the Ghost
            Wallet app.
          </p>
        </div>

        <div className="p-4 rounded-lg bg-[var(--surface)]/50">
          <div className="flex items-center justify-between mb-2">
            <h4 className="text-[color:var(--fg)] font-medium">Receive Address</h4>
            <Badge variant="info">Node Keypair</Badge>
          </div>

          {isLoading && (
            <div className="flex items-center gap-3 py-2">
              <div className="w-5 h-5 rounded-full border-2 border-[var(--rule-strong)] border-t-orange-500 animate-spin" />
              <span className="text-sm text-[color:var(--dim)]">Retrieving Ghost ID...</span>
            </div>
          )}

          {!isLoading && error && (
            <div className="p-3 rounded-lg bg-[var(--red)]/20 border border-[var(--red)]">
              <p className="text-sm text-[color:var(--red)]">{error}</p>
            </div>
          )}

          {!isLoading && !error && ghostId && (
            <div className="flex items-center gap-2">
              <code className="flex-1 break-all rounded bg-[var(--surface)]/70 px-3 py-2 text-sm text-[color:var(--accent)]">
                {ghostId}
              </code>
              <Button variant="secondary" size="sm" onClick={handleCopy}>
                {copied ? 'Copied' : 'Copy'}
              </Button>
            </div>
          )}
        </div>
      </div>
    </Dialog>
  );
}

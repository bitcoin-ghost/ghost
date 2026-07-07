"use client";

import { useWebSocket } from "@/hooks/useWebSocket";

export function ConnectionStatus() {
  const { connectionState, isConnected } = useWebSocket();

  const statusConfig = {
    connected: {
      color: "bg-[var(--green)]",
      label: "Live",
    },
    connecting: {
      color: "bg-[var(--accent)]",
      label: "Connecting",
    },
    disconnected: {
      color: "bg-[var(--fainter)]",
      label: "Offline",
    },
    error: {
      color: "bg-[var(--red)]",
      label: "Error",
    },
  };

  const config = statusConfig[connectionState];

  return (
    <div className="flex items-center gap-2">
      <span className="relative flex h-2 w-2">
        {isConnected && (
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[var(--green)] opacity-75"></span>
        )}
        <span className={`relative inline-flex rounded-full h-2 w-2 ${config.color}`}></span>
      </span>
      <span className="text-xs text-[color:var(--fainter)] hidden sm:inline">{config.label}</span>
    </div>
  );
}

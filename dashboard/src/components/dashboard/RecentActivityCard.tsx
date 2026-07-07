"use client";

import { useState, useEffect } from "react";
import { Card, CardHeader } from "@/components/ui/Card";
import * as api from "@/lib/api";
import type { LogEntry } from "@/types/api";

export function RecentActivityCard() {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchLogs = async () => {
      try {
        const response = await api.getLogs(10, "info");
        setLogs(response.entries);
      } catch (error) {
        console.error("Failed to fetch logs:", error);
      } finally {
        setLoading(false);
      }
    };

    fetchLogs();
    const interval = setInterval(fetchLogs, 5000);
    return () => clearInterval(interval);
  }, []);

  const formatTime = (timestamp: number) => {
    const date = new Date(timestamp * 1000);
    return date.toLocaleTimeString("en-US", {
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  };

  const getLogIcon = (level: string, message: string) => {
    if (message.toLowerCase().includes("block")) return "\u25A0";
    if (message.toLowerCase().includes("peer")) return "\u25CF";
    if (message.toLowerCase().includes("wraith")) return "\u25C6";
    if (message.toLowerCase().includes("settlement")) return "\u25B2";
    return "\u25CB";
  };

  const getLogColor = (level: string) => {
    switch (level) {
      case "error":
        return "text-[color:var(--red)]";
      case "warn":
        return "text-[color:var(--accent)]";
      case "info":
        return "text-[color:var(--accent)]";
      default:
        return "text-[color:var(--dim)]";
    }
  };

  if (loading) {
    return (
      <Card>
        <CardHeader title="Recent Activity" />
        <div className="animate-pulse space-y-2">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="h-4 bg-[var(--surface)] rounded w-full"></div>
          ))}
        </div>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader
        title="Recent Activity"
        action={
          <a href="/logs" className="text-sm text-[color:var(--dim)] hover:text-[color:var(--fg)]">
            View All
          </a>
        }
      />

      <div className="space-y-2 max-h-64 overflow-y-auto">
        {logs.length === 0 ? (
          <p className="text-[color:var(--fainter)] text-sm">No recent activity</p>
        ) : (
          logs.map((log, idx) => (
            <div
              key={idx}
              className="flex items-start gap-3 text-sm py-1 border-b border-[color:var(--rule)]/50 last:border-0"
            >
              <span className="text-[color:var(--fainter)] font-mono text-xs whitespace-nowrap">
                {formatTime(log.timestamp)}
              </span>
              <span className={getLogColor(log.level)}>
                {getLogIcon(log.level, log.message)}
              </span>
              <span className="text-[color:var(--dim)] truncate">{log.message}</span>
            </div>
          ))
        )}
      </div>
    </Card>
  );
}

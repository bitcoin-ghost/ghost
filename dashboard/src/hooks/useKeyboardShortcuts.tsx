"use client";

import { useEffect, useCallback, useState, useMemo } from "react";
import { useRouter } from "next/navigation";

interface ShortcutConfig {
  key: string;
  ctrl?: boolean;
  alt?: boolean;
  shift?: boolean;
  meta?: boolean;
  action: () => void;
  description: string;
}

export function useKeyboardShortcuts() {
  const router = useRouter();
  const [showHelp, setShowHelp] = useState(false);

  const shortcuts: ShortcutConfig[] = useMemo(() => [
    { key: "h", ctrl: true, action: () => router.push("/"), description: "Go to Overview" },
    { key: "n", ctrl: true, action: () => router.push("/network"), description: "Go to Network" },
    { key: "m", ctrl: true, action: () => router.push("/mining"), description: "Go to Mining" },
    { key: "w", ctrl: true, action: () => router.push("/wraith"), description: "Go to Wraith" },
    { key: "p", ctrl: true, action: () => router.push("/payments"), description: "Go to Payments" },
    { key: "s", ctrl: true, action: () => router.push("/settlement"), description: "Go to Settlement" },
    { key: "r", ctrl: true, action: () => router.push("/payouts"), description: "Go to Payouts" },
    { key: "g", ctrl: true, action: () => router.push("/config"), description: "Go to Configuration" },
    { key: "?", ctrl: false, shift: true, action: () => setShowHelp(true), description: "Show shortcuts" },
    { key: "Escape", ctrl: false, action: () => setShowHelp(false), description: "Close dialog" },
  ], [router]);

  const handleKeyDown = useCallback(
    (event: KeyboardEvent) => {
      // Don't trigger shortcuts when typing in inputs
      const target = event.target as HTMLElement;
      if (
        target.tagName === "INPUT" ||
        target.tagName === "TEXTAREA" ||
        target.isContentEditable
      ) {
        return;
      }

      for (const shortcut of shortcuts) {
        const ctrlMatch = shortcut.ctrl ? event.ctrlKey || event.metaKey : !event.ctrlKey && !event.metaKey;
        const altMatch = shortcut.alt ? event.altKey : !event.altKey;
        const shiftMatch = shortcut.shift ? event.shiftKey : !event.shiftKey;
        const keyMatch = event.key.toLowerCase() === shortcut.key.toLowerCase();

        if (keyMatch && ctrlMatch && altMatch && shiftMatch) {
          event.preventDefault();
          shortcut.action();
          return;
        }
      }
    },
    [shortcuts]
  );

  useEffect(() => {
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [handleKeyDown]);

  return { showHelp, setShowHelp, shortcuts };
}

// Keyboard shortcuts help modal component
export function KeyboardShortcutsHelp({
  isOpen,
  onClose,
}: {
  isOpen: boolean;
  onClose: () => void;
}) {
  if (!isOpen) return null;

  const sections = [
    {
      title: "Navigation",
      shortcuts: [
        { keys: ["Ctrl", "H"], description: "Go to Overview" },
        { keys: ["Ctrl", "N"], description: "Go to Network" },
        { keys: ["Ctrl", "M"], description: "Go to Mining" },
        { keys: ["Ctrl", "W"], description: "Go to Wraith" },
        { keys: ["Ctrl", "P"], description: "Go to Payments" },
        { keys: ["Ctrl", "S"], description: "Go to Settlement" },
        { keys: ["Ctrl", "R"], description: "Go to Rewards" },
        { keys: ["Ctrl", "G"], description: "Go to Configuration" },
      ],
    },
    {
      title: "General",
      shortcuts: [
        { keys: ["?"], description: "Show keyboard shortcuts" },
        { keys: ["Esc"], description: "Close dialog" },
      ],
    },
  ];

  return (
    <div
      className="fixed inset-0 bg-black/70 flex items-center justify-center z-[200]"
      onClick={onClose}
    >
      <div
        className="bg-gray-900 border border-gray-800 rounded-lg p-6 max-w-lg w-full mx-4 max-h-[80vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-bold text-gray-100">Keyboard Shortcuts</h2>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-200"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="space-y-6">
          {sections.map((section) => (
            <div key={section.title}>
              <h3 className="text-sm font-medium text-gray-400 mb-2">{section.title}</h3>
              <div className="space-y-2">
                {section.shortcuts.map((shortcut, idx) => (
                  <div key={idx} className="flex items-center justify-between">
                    <span className="text-gray-300">{shortcut.description}</span>
                    <div className="flex gap-1">
                      {shortcut.keys.map((key, keyIdx) => (
                        <kbd
                          key={keyIdx}
                          className="px-2 py-1 bg-gray-800 border border-gray-700 rounded text-xs text-gray-300 font-mono"
                        >
                          {key}
                        </kbd>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>

        <div className="mt-6 pt-4 border-t border-gray-800">
          <p className="text-xs text-gray-500 text-center">
            Press <kbd className="px-1 bg-gray-800 rounded text-gray-400">Esc</kbd> to close
          </p>
        </div>
      </div>
    </div>
  );
}

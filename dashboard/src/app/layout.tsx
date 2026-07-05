import type { Metadata } from "next";
import { IBM_Plex_Sans, IBM_Plex_Mono } from "next/font/google";
import "./globals.css";
import { Providers } from "@/components/Providers";

// IBM Plex matches the public website (ghost-web/style.css). Loaded via
// next/font so the bytes are bundled — no external CDN at runtime.
const plexSans = IBM_Plex_Sans({
  variable: "--font-plex-sans",
  subsets: ["latin"],
  weight: ["300", "400", "500", "600", "700"],
  display: "swap",
});

const plexMono = IBM_Plex_Mono({
  variable: "--font-plex-mono",
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  display: "swap",
});

export const metadata: Metadata = {
  title: "Ghost Node",
  description: "Ghost Node — the familiar spirit that watches your Ghost node",
};

// Inline script that runs before paint so there's no flash of wrong theme on
// load. Order: explicit user choice in localStorage > dark (default).
// Dark is the default regardless of OS preference; light mode is opt-in only.
const themeBootstrap = `
(function() {
  try {
    var stored = localStorage.getItem('ghost-theme');
    var theme = stored || 'dark';
    document.documentElement.setAttribute('data-theme', theme);
  } catch (e) {
    document.documentElement.setAttribute('data-theme', 'dark');
  }
})();
`;

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeBootstrap }} />
      </head>
      <body className={`${plexSans.variable} ${plexMono.variable} antialiased`}>
        <Providers>
          {children}
        </Providers>
      </body>
    </html>
  );
}

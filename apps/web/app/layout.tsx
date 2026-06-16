import type { Metadata } from "next";
import "./styles.css";

export const metadata: Metadata = {
  title: "AgentFence",
  description: "Local permissions and tool governance for AI coding agents."
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}


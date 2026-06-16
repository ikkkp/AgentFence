import type { ReactNode } from "react";

export function StatusBadge({
  tone,
  children,
}: {
  tone: "good" | "warn" | "bad" | "neutral";
  children: ReactNode;
}) {
  return <span className={`af-badge af-badge-${tone}`}>{children}</span>;
}

export function Metric({
  label,
  value,
  detail,
}: {
  label: string;
  value: string;
  detail?: string;
}) {
  return (
    <div className="af-metric">
      <span>{label}</span>
      <strong>{value}</strong>
      {detail ? <small>{detail}</small> : null}
    </div>
  );
}


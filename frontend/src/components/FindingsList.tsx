import type { Finding } from "@/types/scan";

const SEVERITY_STYLES: Record<string, string> = {
  high: "border-red-500 bg-red-950 text-red-200",
  medium: "border-yellow-500 bg-yellow-950 text-yellow-200",
  low: "border-blue-500 bg-blue-950 text-blue-200",
};

interface FindingsListProps {
  findings: Finding[];
}

export default function FindingsList({ findings }: FindingsListProps) {
  if (findings.length === 0) {
    return <p className="text-neutral-400">No findings yet. Run a scan to see results here.</p>;
  }

  return (
    <div className="flex flex-col gap-3">
      {findings.map((finding, index) => (
        <div
          key={`${finding.detector}-${finding.rule_id}-${index}`}
          className={`rounded-lg border p-4 ${SEVERITY_STYLES[finding.severity] ?? "border-neutral-600 bg-neutral-900 text-neutral-200"}`}
        >
          <div className="flex items-center justify-between text-sm font-semibold uppercase tracking-wide">
            <span>{finding.detector}</span>
            <span>{finding.severity}</span>
          </div>
          <p className="mt-1 font-medium">{finding.vulnerability_type}</p>
          <p className="mt-1 text-sm opacity-90">{finding.message}</p>
          {finding.line_number !== null && (
            <p className="mt-1 text-xs opacity-70">Line {finding.line_number}</p>
          )}
        </div>
      ))}
    </div>
  );
}
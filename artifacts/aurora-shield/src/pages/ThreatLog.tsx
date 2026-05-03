import { useState } from "react";
import { Shell } from "@/components/layout/Shell";
import { useGetRecentThreats, getGetRecentThreatsQueryKey, ThreatEvent } from "@workspace/api-client-react";
import { Search, Filter, ShieldAlert } from "lucide-react";
import { format } from "date-fns";

function getRiskColor(level: string) {
  switch (level) {
    case 'critical': return 'text-destructive border-destructive bg-destructive/10';
    case 'high': return 'text-orange-500 border-orange-500 bg-orange-500/10';
    case 'medium': return 'text-yellow-500 border-yellow-500 bg-yellow-500/10';
    case 'low': return 'text-blue-400 border-blue-400 bg-blue-400/10';
    case 'safe': return 'text-green-500 border-green-500 bg-green-500/10';
    default: return 'text-muted-foreground border-border bg-muted/10';
  }
}

export default function ThreatLog() {
  const { data: threats, isLoading } = useGetRecentThreats({ query: { queryKey: getGetRecentThreatsQueryKey() } });
  const [filterType, setFilterType] = useState<string>("all");

  const filteredThreats = threats?.filter(t => filterType === "all" || t.type === filterType) || [];

  return (
    <Shell>
      <div className="flex flex-col md:flex-row md:justify-between md:items-end border-b border-border pb-4 mb-6 gap-4">
        <div>
          <h1 className="text-2xl font-bold uppercase tracking-wider text-foreground flex items-center gap-2">
            <ShieldAlert className="text-orange-500 w-6 h-6" /> Threat Log
          </h1>
          <p className="text-muted-foreground text-sm mt-1">Historical threat detection events</p>
        </div>
        
        <div className="flex gap-2">
          <select 
            className="bg-card border border-border text-sm rounded-md px-3 py-1.5 focus:outline-none focus:ring-1 focus:ring-primary text-foreground font-mono"
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
          >
            <option value="all">ALL TYPES</option>
            <option value="prompt_injection">PROMPT INJECTION</option>
            <option value="phishing">PHISHING</option>
            <option value="suspicious_url">SUSPICIOUS URL</option>
          </select>
        </div>
      </div>

      <div className="border border-border rounded-md bg-card overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-muted-foreground animate-pulse">Loading logs...</div>
        ) : filteredThreats.length > 0 ? (
          <table className="w-full text-sm text-left">
            <thead className="bg-muted/30 border-b border-border text-xs uppercase tracking-wider text-muted-foreground">
              <tr>
                <th className="px-4 py-3">ID</th>
                <th className="px-4 py-3">Timestamp</th>
                <th className="px-4 py-3">Type</th>
                <th className="px-4 py-3">Risk Level</th>
                <th className="px-4 py-3">Score</th>
                <th className="px-4 py-3">Summary</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filteredThreats.map((threat) => (
                <tr key={threat.id} className="hover:bg-muted/10 transition-colors">
                  <td className="px-4 py-3 font-mono text-muted-foreground text-xs">#{threat.id.toString().padStart(6, '0')}</td>
                  <td className="px-4 py-3 font-mono text-muted-foreground whitespace-nowrap">
                    {format(new Date(threat.detectedAt), "yyyy-MM-dd HH:mm:ss")}
                  </td>
                  <td className="px-4 py-3 font-mono uppercase tracking-wider text-xs">{threat.type.replace('_', ' ')}</td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-1 text-[10px] uppercase tracking-wider font-bold border rounded ${getRiskColor(threat.riskLevel)}`}>
                      {threat.riskLevel}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs">
                    {threat.riskScore.toFixed(3)}
                  </td>
                  <td className="px-4 py-3 text-foreground font-mono text-xs max-w-md truncate" title={threat.summary}>
                    {threat.summary}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="p-8 text-center text-muted-foreground">No records found matching criteria.</div>
        )}
      </div>
    </Shell>
  );
}

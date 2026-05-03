import { useState } from "react";
import { Shell } from "@/components/layout/Shell";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { useGetAnalysisStats, getGetAnalysisStatsQueryKey, useGetRecentThreats, getGetRecentThreatsQueryKey, ThreatEvent } from "@workspace/api-client-react";
import { AlertTriangle, ShieldCheck, ShieldAlert, Activity, Globe, MessageSquare } from "lucide-react";
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

export default function Dashboard() {
  const { data: stats, isLoading: statsLoading } = useGetAnalysisStats({ query: { queryKey: getGetAnalysisStatsQueryKey() } });
  const { data: threats, isLoading: threatsLoading } = useGetRecentThreats({ query: { queryKey: getGetRecentThreatsQueryKey() } });

  return (
    <Shell>
      <div className="flex justify-between items-center border-b border-border pb-4 mb-6">
        <div>
          <h1 className="text-2xl font-bold uppercase tracking-wider text-foreground flex items-center gap-2">
            <Activity className="text-primary w-6 h-6" /> System Overview
          </h1>
          <p className="text-muted-foreground text-sm mt-1">Real-time threat telemetry</p>
        </div>
        <div className="flex items-center gap-2 px-3 py-1.5 border border-primary/30 bg-primary/10 text-primary rounded-md text-sm font-bold tracking-wide shadow-[0_0_10px_rgba(0,255,255,0.2)]">
          <ShieldCheck className="w-4 h-4" /> SHIELD ACTIVE
        </div>
      </div>
      
      {statsLoading ? (
        <div className="h-32 border border-border bg-card animate-pulse rounded-md"></div>
      ) : stats ? (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
          <Card className="border-border bg-card/50">
            <CardHeader className="pb-2">
              <CardTitle className="text-xs text-muted-foreground uppercase tracking-wider">Total Scans</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-mono text-foreground">{stats.totalScans.toLocaleString()}</div>
            </CardContent>
          </Card>
          <Card className="border-border bg-card/50">
            <CardHeader className="pb-2">
              <CardTitle className="text-xs text-muted-foreground uppercase tracking-wider">Prompt Injections</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-mono text-primary flex items-center gap-2">
                <MessageSquare className="w-5 h-5 opacity-50" />
                {stats.promptInjections.toLocaleString()}
              </div>
            </CardContent>
          </Card>
          <Card className="border-border bg-card/50">
            <CardHeader className="pb-2">
              <CardTitle className="text-xs text-muted-foreground uppercase tracking-wider">Phishing Sites</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-mono text-orange-500 flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 opacity-50" />
                {stats.phishingDetected.toLocaleString()}
              </div>
            </CardContent>
          </Card>
          <Card className="border-border bg-card/50">
            <CardHeader className="pb-2">
              <CardTitle className="text-xs text-muted-foreground uppercase tracking-wider">Suspicious URLs</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-mono text-destructive flex items-center gap-2">
                <Globe className="w-5 h-5 opacity-50" />
                {stats.suspiciousUrls.toLocaleString()}
              </div>
            </CardContent>
          </Card>
        </div>
      ) : null}

      <div className="space-y-4">
        <h2 className="text-sm font-bold uppercase tracking-widest text-muted-foreground border-b border-border pb-2">Recent Threat Feed</h2>
        
        {threatsLoading ? (
           <div className="h-64 border border-border bg-card animate-pulse rounded-md"></div>
        ) : threats && threats.length > 0 ? (
          <div className="border border-border rounded-md bg-card overflow-hidden">
            <table className="w-full text-sm text-left">
              <thead className="bg-muted/30 border-b border-border text-xs uppercase tracking-wider text-muted-foreground">
                <tr>
                  <th className="px-4 py-3">Timestamp</th>
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Risk</th>
                  <th className="px-4 py-3">Summary</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {threats.map((threat) => (
                  <tr key={threat.id} className="hover:bg-muted/10 transition-colors">
                    <td className="px-4 py-3 font-mono text-muted-foreground whitespace-nowrap">
                      {format(new Date(threat.detectedAt), "HH:mm:ss.SSS")}
                    </td>
                    <td className="px-4 py-3 font-mono uppercase tracking-wider">{threat.type.replace('_', ' ')}</td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-1 text-[10px] uppercase tracking-wider font-bold border rounded ${getRiskColor(threat.riskLevel)}`}>
                        {threat.riskLevel}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-foreground font-mono text-xs max-w-md truncate" title={threat.summary}>
                      {threat.summary}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="text-center py-12 border border-border border-dashed rounded-md text-muted-foreground">
            <ShieldCheck className="w-8 h-8 mx-auto mb-2 opacity-50" />
            <p>No recent threats detected.</p>
          </div>
        )}
      </div>
    </Shell>
  );
}

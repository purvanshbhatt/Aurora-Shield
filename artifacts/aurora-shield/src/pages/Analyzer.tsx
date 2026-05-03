import { useState } from "react";
import { Shell } from "@/components/layout/Shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { useAnalyzePrompt, useAnalyzePhishing, useAnalyzeUrl } from "@workspace/api-client-react";
import { Search, ShieldAlert, Globe, MessageSquare, Loader2, AlertTriangle, CheckCircle2 } from "lucide-react";

export default function Analyzer() {
  const [activeTab, setActiveTab] = useState<"prompt" | "phishing" | "url">("prompt");
  const [inputData, setInputData] = useState("");
  const [results, setResults] = useState<any>(null);

  const analyzePrompt = useAnalyzePrompt();
  const analyzePhishing = useAnalyzePhishing();
  const analyzeUrl = useAnalyzeUrl();

  const isPending = analyzePrompt.isPending || analyzePhishing.isPending || analyzeUrl.isPending;

  const handleAnalyze = async () => {
    if (!inputData.trim()) return;
    setResults(null);

    try {
      if (activeTab === "prompt") {
        const res = await analyzePrompt.mutateAsync({ data: { text: inputData } });
        setResults(res);
      } else if (activeTab === "phishing") {
        const res = await analyzePhishing.mutateAsync({ data: { content: inputData } });
        setResults(res);
      } else if (activeTab === "url") {
        const res = await analyzeUrl.mutateAsync({ data: { urls: [inputData] } });
        setResults(res);
      }
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <Shell>
      <div className="border-b border-border pb-4 mb-6">
        <h1 className="text-2xl font-bold uppercase tracking-wider text-foreground flex items-center gap-2">
          <Search className="text-primary w-6 h-6" /> Manual Analyzer
        </h1>
        <p className="text-muted-foreground text-sm mt-1">Deep-scan text or URLs for targeted analysis</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="space-y-4">
          <div className="flex border-b border-border">
            <button 
              className={`px-4 py-2 font-mono text-xs uppercase tracking-wider flex items-center gap-2 border-b-2 transition-colors ${activeTab === 'prompt' ? 'border-primary text-primary bg-primary/5' : 'border-transparent text-muted-foreground hover:text-foreground'}`}
              onClick={() => { setActiveTab("prompt"); setResults(null); setInputData(""); }}
            >
              <MessageSquare className="w-4 h-4" /> Prompt Injection
            </button>
            <button 
              className={`px-4 py-2 font-mono text-xs uppercase tracking-wider flex items-center gap-2 border-b-2 transition-colors ${activeTab === 'phishing' ? 'border-orange-500 text-orange-500 bg-orange-500/5' : 'border-transparent text-muted-foreground hover:text-foreground'}`}
              onClick={() => { setActiveTab("phishing"); setResults(null); setInputData(""); }}
            >
              <ShieldAlert className="w-4 h-4" /> Phishing Content
            </button>
            <button 
              className={`px-4 py-2 font-mono text-xs uppercase tracking-wider flex items-center gap-2 border-b-2 transition-colors ${activeTab === 'url' ? 'border-destructive text-destructive bg-destructive/5' : 'border-transparent text-muted-foreground hover:text-foreground'}`}
              onClick={() => { setActiveTab("url"); setResults(null); setInputData(""); }}
            >
              <Globe className="w-4 h-4" /> Suspicious URL
            </button>
          </div>

          <div className="bg-card border border-border rounded-md p-1">
            {activeTab === "url" ? (
              <Input 
                placeholder="Enter URL (e.g. https://example.com)" 
                className="font-mono text-sm border-0 focus-visible:ring-0 bg-transparent"
                value={inputData}
                onChange={(e) => setInputData(e.target.value)}
              />
            ) : (
              <Textarea 
                placeholder={`Paste ${activeTab === 'prompt' ? 'prompt text' : 'email or page content'} here...`}
                className="min-h-[200px] font-mono text-sm border-0 focus-visible:ring-0 resize-y bg-transparent"
                value={inputData}
                onChange={(e) => setInputData(e.target.value)}
              />
            )}
          </div>
          
          <Button 
            onClick={handleAnalyze} 
            disabled={isPending || !inputData.trim()}
            className="w-full font-mono uppercase tracking-widest font-bold"
            variant={activeTab === 'prompt' ? 'default' : activeTab === 'phishing' ? 'secondary' : 'destructive'}
          >
            {isPending ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <Search className="w-4 h-4 mr-2" />}
            Execute Scan
          </Button>
        </div>

        <div>
          {results ? (
            <Card className="border-border bg-card/50 h-full">
              <CardHeader className="border-b border-border pb-4 bg-muted/10">
                <CardTitle className="text-sm font-mono uppercase tracking-widest flex items-center justify-between">
                  Analysis Results
                  <span className={`px-2 py-1 text-[10px] uppercase border rounded ${
                    results.riskLevel === 'critical' ? 'text-destructive border-destructive bg-destructive/10' :
                    results.riskLevel === 'high' ? 'text-orange-500 border-orange-500 bg-orange-500/10' :
                    results.riskLevel === 'medium' ? 'text-yellow-500 border-yellow-500 bg-yellow-500/10' :
                    results.riskLevel === 'low' ? 'text-blue-400 border-blue-400 bg-blue-400/10' :
                    'text-green-500 border-green-500 bg-green-500/10'
                  }`}>
                    {results.riskLevel || "SAFE"}
                  </span>
                </CardTitle>
              </CardHeader>
              <CardContent className="pt-4 font-mono text-sm space-y-4">
                <div className="grid grid-cols-2 gap-4 border-b border-border pb-4">
                  <div>
                    <span className="text-muted-foreground text-xs block mb-1">RISK SCORE</span>
                    <span className={`text-2xl ${(results.riskScore || results.overallRiskScore) > 0.7 ? 'text-destructive' : 'text-primary'}`}>
                      {((results.riskScore || results.overallRiskScore || 0) * 100).toFixed(1)}%
                    </span>
                  </div>
                  <div>
                    <span className="text-muted-foreground text-xs block mb-1">CACHE STATUS</span>
                    <span className="text-muted-foreground">{results.cached ? 'HIT' : 'MISS'}</span>
                  </div>
                </div>

                {activeTab === 'prompt' && results.patterns && (
                  <div>
                    <span className="text-muted-foreground text-xs block mb-2">DETECTED PATTERNS</span>
                    {results.patterns.length > 0 ? (
                      <ul className="list-disc pl-4 space-y-1 text-destructive">
                        {results.patterns.map((p: string, i: number) => <li key={i}>{p}</li>)}
                      </ul>
                    ) : (
                      <span className="text-green-500 flex items-center gap-1"><CheckCircle2 className="w-3 h-3" /> No patterns detected</span>
                    )}
                    {results.recommendation && (
                      <div className="mt-4 p-3 bg-muted/20 border border-border rounded text-muted-foreground">
                        {results.recommendation}
                      </div>
                    )}
                  </div>
                )}

                {activeTab === 'phishing' && results.indicators && (
                  <div>
                    <span className="text-muted-foreground text-xs block mb-2">PHISHING INDICATORS</span>
                    {results.indicators.length > 0 ? (
                      <ul className="list-disc pl-4 space-y-1 text-orange-500">
                        {results.indicators.map((p: string, i: number) => <li key={i}>{p}</li>)}
                      </ul>
                    ) : (
                      <span className="text-green-500 flex items-center gap-1"><CheckCircle2 className="w-3 h-3" /> No indicators found</span>
                    )}
                  </div>
                )}
                
                {activeTab === 'url' && results.urlResults && (
                  <div>
                    <span className="text-muted-foreground text-xs block mb-2">URL ANALYSIS</span>
                    {results.urlResults.map((r: any, i: number) => (
                      <div key={i} className="mb-2 p-2 border border-border rounded bg-muted/10 break-all">
                        <div className="text-muted-foreground mb-1">{r.url}</div>
                        {r.flags.length > 0 ? (
                          <div className="text-destructive text-xs">Flags: {r.flags.join(", ")}</div>
                        ) : (
                          <div className="text-green-500 text-xs">Clean</div>
                        )}
                      </div>
                    ))}
                  </div>
                )}

              </CardContent>
            </Card>
          ) : (
            <div className="h-full min-h-[300px] border border-border border-dashed rounded-md flex items-center justify-center text-muted-foreground bg-card/20">
              <div className="text-center font-mono text-sm">
                <AlertTriangle className="w-8 h-8 mx-auto mb-2 opacity-50" />
                <p>AWAITING INPUT DATA</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </Shell>
  );
}

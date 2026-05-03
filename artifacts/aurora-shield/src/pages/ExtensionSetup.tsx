import { Shell } from "@/components/layout/Shell";
import { Settings, Download, Terminal, Code } from "lucide-react";

export default function ExtensionSetup() {
  return (
    <Shell>
      <div className="border-b border-border pb-4 mb-6">
        <h1 className="text-2xl font-bold uppercase tracking-wider text-foreground flex items-center gap-2">
          <Settings className="text-primary w-6 h-6" /> Extension Setup
        </h1>
        <p className="text-muted-foreground text-sm mt-1">Deploy AuroraShield to your browser endpoints</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        <div className="space-y-6">
          <div>
            <h2 className="text-lg font-mono text-foreground mb-3 flex items-center gap-2 border-b border-border pb-2">
              <Download className="w-5 h-5 text-primary" /> Installation (Developer Mode)
            </h2>
            <ol className="list-decimal pl-5 space-y-4 text-sm text-muted-foreground font-mono">
              <li>Download the AuroraShield extension package.</li>
              <li>Extract the contents to a secure directory (e.g. <code className="text-primary bg-primary/10 px-1 py-0.5 rounded">~/sec/aurora-shield</code>).</li>
              <li>Open your browser's extension management page (e.g. <code className="text-foreground">chrome://extensions</code>).</li>
              <li>Enable <strong className="text-foreground">Developer mode</strong> in the top right corner.</li>
              <li>Click <strong className="text-foreground">Load unpacked</strong> and select the extracted directory.</li>
              <li>Pin the AuroraShield icon to your toolbar for quick access.</li>
            </ol>
          </div>
          
          <div className="bg-primary/5 border border-primary/20 rounded-md p-4">
            <h3 className="font-bold text-primary font-mono text-sm mb-2">API Configuration</h3>
            <p className="text-sm text-muted-foreground font-mono mb-3">Ensure the extension points to this SOC interface URL in its settings.</p>
            <div className="bg-background border border-border p-2 rounded text-xs font-mono text-foreground flex justify-between items-center overflow-x-auto">
              <code>{window.location.origin}</code>
            </div>
          </div>
        </div>

        <div className="space-y-4">
          <h2 className="text-lg font-mono text-foreground mb-3 flex items-center gap-2 border-b border-border pb-2">
            <Code className="w-5 h-5 text-primary" /> Core Files
          </h2>
          
          <div className="space-y-4">
            <div className="border border-border rounded overflow-hidden">
              <div className="bg-muted/30 px-3 py-1 border-b border-border font-mono text-xs text-muted-foreground flex items-center gap-2">
                <Terminal className="w-3 h-3" /> manifest.json
              </div>
              <div className="p-3 bg-card font-mono text-xs text-foreground overflow-x-auto">
<pre><code>{`{
  "manifest_version": 3,
  "name": "AuroraShield Security",
  "version": "1.0.0",
  "description": "Real-time AI-powered browser security shield",
  "permissions": ["activeTab", "webRequest", "storage"],
  "host_permissions": ["<all_urls>"],
  "background": {
    "service_worker": "background.js"
  },
  "content_scripts": [
    {
      "matches": ["<all_urls>"],
      "js": ["content.js"]
    }
  ]
}`}</code></pre>
              </div>
            </div>

            <div className="border border-border rounded overflow-hidden">
              <div className="bg-muted/30 px-3 py-1 border-b border-border font-mono text-xs text-muted-foreground flex items-center gap-2">
                <Terminal className="w-3 h-3" /> background.js
              </div>
              <div className="p-3 bg-card font-mono text-xs text-blue-400 overflow-x-auto">
<pre><code>{`// Intercepts and analyzes requests
chrome.webRequest.onBeforeRequest.addListener(
  async (details) => {
    // Send URL to AuroraShield API for scanning
    const result = await fetch("YOUR_API_URL/analyze/url", {
      method: "POST",
      body: JSON.stringify({ urls: [details.url] })
    });
    // ... handling logic
  },
  { urls: ["<all_urls>"] },
  ["blocking"]
);`}</code></pre>
              </div>
            </div>
          </div>
        </div>
      </div>
    </Shell>
  );
}

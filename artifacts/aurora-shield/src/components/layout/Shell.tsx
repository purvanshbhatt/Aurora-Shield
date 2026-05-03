import { Link, useLocation } from "wouter";
import { Shield, ShieldAlert, List, Activity, Settings } from "lucide-react";

export function Shell({ children }: { children: React.ReactNode }) {
  const [location] = useLocation();

  const navItems = [
    { href: "/", label: "Dashboard", icon: Activity },
    { href: "/threats", label: "Threat Log", icon: List },
    { href: "/analyzer", label: "Analyzer", icon: ShieldAlert },
    { href: "/extension", label: "Extension Setup", icon: Settings },
  ];

  return (
    <div className="flex h-screen w-full bg-background text-foreground overflow-hidden font-mono">
      {/* Sidebar */}
      <div className="w-64 border-r border-border bg-card flex flex-col">
        <div className="p-4 border-b border-border flex items-center gap-3">
          <Shield className="w-6 h-6 text-primary" />
          <div>
            <h1 className="font-bold text-sm tracking-wider uppercase text-foreground">AURORA<span className="text-primary">SHIELD</span></h1>
            <p className="text-[10px] text-muted-foreground uppercase tracking-widest">SOC Interface</p>
          </div>
        </div>
        
        <nav className="flex-1 p-4 space-y-1">
          {navItems.map((item) => {
            const active = location === item.href;
            const Icon = item.icon;
            return (
              <Link 
                key={item.href} 
                href={item.href}
                className={`flex items-center gap-3 px-3 py-2 text-sm rounded-md transition-colors ${
                  active 
                    ? "bg-primary/10 text-primary border border-primary/20" 
                    : "text-muted-foreground hover:text-foreground hover:bg-muted/50 border border-transparent"
                }`}
              >
                <Icon className="w-4 h-4" />
                {item.label}
              </Link>
            );
          })}
        </nav>
        
        <div className="p-4 border-t border-border">
          <div className="flex items-center justify-between text-xs">
            <span className="text-muted-foreground">SYSTEM STATUS</span>
            <span className="flex items-center gap-1.5 text-primary">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-primary"></span>
              </span>
              ONLINE
            </span>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <main className="flex-1 overflow-auto bg-background p-6">
        <div className="max-w-7xl mx-auto space-y-6">
          {children}
        </div>
      </main>
    </div>
  );
}

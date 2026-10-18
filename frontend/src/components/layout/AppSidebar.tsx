"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { AttackPathLogo } from "../brand/AttackPathLogo";
import { api } from "@/lib/api";
import { ReadyResponse } from "@/lib/types";
import {
  Activity,
  GitBranch,
  ShieldAlert,
  LogOut,
  User,
} from "lucide-react";

export function AppSidebar() {
  const pathname = usePathname();
  const [readiness, setReadiness] = useState<ReadyResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [apiOnline, setApiOnline] = useState<boolean>(true);
  const [dbReady, setDbReady] = useState<boolean>(true);
  const [userName, setUserName] = useState<string>("A. Vance");
  const [userRole, setUserRole] = useState<string>("analyst");

  useEffect(() => {
    // Read session-based demo profile
    if (typeof window !== "undefined") {
      const storedUser = sessionStorage.getItem("attackpath_user");
      const storedRole = sessionStorage.getItem("attackpath_role");
      if (storedUser) setUserName(storedUser);
      if (storedRole) setUserRole(storedRole);
    }

    let mounted = true;

    async function checkHealth() {
      try {
        // Step 1: Check FastAPI liveness
        await api.getHealth();
        if (!mounted) return;
        setApiOnline(true);

        // Step 2: Check FalkorDB readiness
        try {
          const readyRes = await api.getReadiness();
          if (mounted) {
            setReadiness(readyRes);
            setDbReady(true);
            setLoading(false);
          }
        } catch {
          if (mounted) {
            setDbReady(false);
            setLoading(false);
          }
        }
      } catch {
        if (mounted) {
          setApiOnline(false);
          setDbReady(false);
          setLoading(false);
        }
      }
    }

    checkHealth();
    const interval = setInterval(checkHealth, 15000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  const navItems = [
    {
      name: "Investigations",
      href: "/investigate",
      icon: Activity,
    },
    {
      name: "Attack Graph",
      href: "/investigate",
      icon: GitBranch,
    },
    {
      name: "Remediation",
      href: "/remediate",
      icon: ShieldAlert,
    },
  ];

  return (
    <aside className="fixed left-0 top-0 bottom-0 w-64 bg-white z-50 flex flex-col justify-between border-r border-[#E3DDD2] shadow-[0_1px_4px_rgba(0,0,0,0.03)] select-none">
      <div className="flex flex-col">
        {/* Brand Header */}
        <div className="h-14 px-5 flex items-center border-b border-[#E3DDD2]">
          <Link href="/investigate" className="hover:opacity-95 transition-opacity">
            <AttackPathLogo size="sm" showSubtitle={true} />
          </Link>
        </div>

        {/* Navigation Items */}
        <nav className="flex flex-col gap-1 px-3 py-4">
          {navItems.map((item) => {
            const isActive = pathname === item.href;
            const Icon = item.icon;
            return (
              <Link
                key={item.name}
                href={item.href}
                className={`flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
                  isActive
                    ? "bg-[#FAF7F0] text-[#282B2A] font-semibold border-l-2 border-[#E85D4A] shadow-sm"
                    : "text-[#686D6B] hover:bg-[#FAF7F0] hover:text-[#282B2A]"
                }`}
              >
                <Icon
                  className={`w-4 h-4 ${
                    isActive ? "text-[#E85D4A]" : "text-[#686D6B]"
                  }`}
                />
                <span>{item.name}</span>
              </Link>
            );
          })}
        </nav>
      </div>

      {/* Sidebar Bottom Status & Profile */}
      <div className="flex flex-col gap-3 p-4 bg-[#FAF7F0] border-t border-[#E3DDD2]">
        <div className="flex items-center justify-between px-2.5 py-1.5 rounded-md bg-white border border-[#E3DDD2]">
          <span className="font-mono text-[9px] uppercase tracking-wider text-[#686D6B] font-medium">
            Telemetry Mode
          </span>
          <span className="px-1.5 py-0.5 rounded bg-[#EEF7F5] border border-[#32877A]/30 font-mono text-[9px] text-[#32877A] font-semibold">
            SYNTHETIC DEMO
          </span>
        </div>

        {/* Engine Connectivity Status */}
        <div className="flex flex-col gap-1 px-1">
          <div className="flex items-center gap-2">
            <span className="relative flex h-2 w-2">
              <span
                className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
                  !apiOnline || !dbReady ? "bg-[#BA1A1A]" : "bg-[#32877A]"
                }`}
              />
              <span
                className={`relative inline-flex rounded-full h-2 w-2 ${
                  !apiOnline || !dbReady ? "bg-[#BA1A1A]" : "bg-[#32877A]"
                }`}
              />
            </span>
            <span className="font-mono text-[11px] text-[#282B2A] font-medium">
              {loading
                ? "Connecting..."
                : !apiOnline
                ? "Backend: Stopped (Offline)"
                : !dbReady
                ? "FalkorDB: Unavailable (503)"
                : `FalkorDB: ${readiness?.status || "Ready"}`}
            </span>
          </div>
          <span
            className="font-mono text-[10px] text-[#686D6B] truncate"
            title={
              !apiOnline
                ? "FastAPI service offline at http://127.0.0.1:8000"
                : !dbReady
                ? "FastAPI running • FalkorDB connection failed"
                : `Graph: ${readiness?.graph || "attackpath_baseline"}`
            }
          >
            {!apiOnline
              ? "FastAPI (127.0.0.1:8000)"
              : !dbReady
              ? "Database Offline"
              : `Graph: ${readiness?.graph || "attackpath_baseline"}`}
          </span>
        </div>

        <div className="h-px bg-[#E3DDD2] w-full" />

        {/* User Profile Bar */}
        <div className="flex items-center justify-between px-1">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-[#FDF2F0] border border-[#E85D4A]/30 flex items-center justify-center font-bold text-[#E85D4A]">
              <User className="w-4 h-4 text-[#E85D4A]" />
            </div>
            <div className="flex flex-col">
              <span className="text-[12px] font-semibold text-[#282B2A] leading-tight">
                {userName}
              </span>
              <span
                className="font-mono text-[10px] text-[#686D6B] leading-none"
                title="Frontend demo session profile. Server-side RBAC is not enforced."
              >
                {userRole === "viewer" ? "Security Viewer (Demo)" : "SecOps Analyst (Demo)"}
              </span>
            </div>
          </div>
          <Link
            href="/"
            onClick={() => {
              if (typeof window !== "undefined") {
                sessionStorage.removeItem("attackpath_user");
                sessionStorage.removeItem("attackpath_role");
              }
            }}
            title="Sign out / Switch account"
            className="text-[#969B98] hover:text-[#282B2A] transition-colors p-1"
          >
            <LogOut className="w-3.5 h-3.5" />
          </Link>
        </div>
      </div>
    </aside>
  );
}

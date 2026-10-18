"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation";
import { AttackPathLogo } from "@/components/brand/AttackPathLogo";
import {
  User,
  Lock,
  Eye,
  EyeOff,
  ArrowRight,
  Info,
  CheckCircle,
  AlertTriangle,
  X,
} from "lucide-react";

export function SignInView() {
  const router = useRouter();
  const [username, setUsername] = useState("a_vance");
  const [password, setPassword] = useState("••••••••••••••••");
  const [showPassword, setShowPassword] = useState(false);
  const [role, setRole] = useState<"analyst" | "viewer">("analyst");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);
  const [showForgotNotice, setShowForgotNotice] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);
    setShowForgotNotice(false);

    if (!username.trim() || !password.trim()) {
      setAuthError("Please provide both username and password.");
      return;
    }

    if (username.trim().toLowerCase() !== "a_vance") {
      setAuthError(
        "Invalid credentials for demo sandbox. Please use the pre-configured SecOps profile (a_vance)."
      );
      return;
    }

    setIsSubmitting(true);
    if (typeof window !== "undefined") {
      sessionStorage.setItem("attackpath_user", "A. Vance");
      sessionStorage.setItem("attackpath_role", role);
    }

    setTimeout(() => {
      router.push("/investigate");
    }, 350);
  };

  const handleAutofillDemo = () => {
    setUsername("a_vance");
    setPassword("••••••••••••••••");
    setRole("analyst");
    setAuthError(null);
    setShowForgotNotice(false);
  };

  return (
    <div className="min-h-screen w-full flex items-center justify-center p-4 sm:p-6 md:p-10 text-[#282B2A] antialiased selection:bg-[#E85D4A] selection:text-white bg-[#ECE5D8]">
      {/* Main Canvas Container */}
      <main className="relative w-full max-w-[1360px] min-h-[760px] lg:h-[840px] rounded-[32px] overflow-hidden shadow-[0_32px_80px_-16px_rgba(40,43,42,0.22),0_12px_32px_-8px_rgba(40,43,42,0.12)] border border-[#E3DDD2]/70 bg-gradient-to-br from-[#2D1B28] via-[#4A2033] via-[#7C2C39] via-[#C84A3B] to-[#F18D45] flex flex-col lg:flex-row">
        {/* Background Artwork Layer */}
        <div
          className="absolute inset-0 pointer-events-none overflow-hidden select-none"
          aria-hidden="true"
        >
          <svg
            className="w-full h-full object-cover"
            viewBox="0 0 1440 900"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
            preserveAspectRatio="xMidYMid slice"
          >
            <defs>
              <radialGradient
                id="coralGlow"
                cx="0"
                cy="0"
                r="1"
                gradientUnits="userSpaceOnUse"
                gradientTransform="translate(380 440) rotate(25) scale(550 480)"
              >
                <stop stopColor="#E85D4A" stopOpacity="0.85" />
                <stop offset="0.45" stopColor="#D94E3B" stopOpacity="0.6" />
                <stop offset="0.8" stopColor="#7C5CBF" stopOpacity="0.3" />
                <stop offset="1" stopColor="#341A28" stopOpacity="0" />
              </radialGradient>

              <radialGradient
                id="amberGlow"
                cx="0"
                cy="0"
                r="1"
                gradientUnits="userSpaceOnUse"
                gradientTransform="translate(850 220) rotate(50) scale(480 420)"
              >
                <stop stopColor="#F2AA38" stopOpacity="0.75" />
                <stop offset="0.5" stopColor="#D99A28" stopOpacity="0.4" />
                <stop offset="1" stopColor="#C84A3B" stopOpacity="0" />
              </radialGradient>

              <radialGradient
                id="tealGlow"
                cx="0"
                cy="0"
                r="1"
                gradientUnits="userSpaceOnUse"
                gradientTransform="translate(240 780) rotate(-30) scale(460 380)"
              >
                <stop stopColor="#3FA696" stopOpacity="0.65" />
                <stop offset="0.6" stopColor="#32877A" stopOpacity="0.35" />
                <stop offset="1" stopColor="#2D1B28" stopOpacity="0" />
              </radialGradient>

              <linearGradient
                id="waveGrad1"
                x1="120"
                y1="80"
                x2="880"
                y2="820"
                gradientUnits="userSpaceOnUse"
              >
                <stop stopColor="#FFF5EA" stopOpacity="0.3" />
                <stop offset="0.25" stopColor="#E85D4A" stopOpacity="0.5" />
                <stop offset="0.6" stopColor="#7C5CBF" stopOpacity="0.45" />
                <stop offset="1" stopColor="#282B2A" stopOpacity="0.75" />
              </linearGradient>

              <linearGradient
                id="pathCoralStroke"
                x1="140"
                y1="620"
                x2="680"
                y2="340"
                gradientUnits="userSpaceOnUse"
              >
                <stop stopColor="#FFF0ED" stopOpacity="0.95" />
                <stop offset="0.5" stopColor="#E85D4A" />
                <stop offset="1" stopColor="#F2AA38" />
              </linearGradient>

              <linearGradient
                id="pathAmberStroke"
                x1="380"
                y1="520"
                x2="720"
                y2="680"
                gradientUnits="userSpaceOnUse"
              >
                <stop stopColor="#D99A28" />
                <stop offset="0.7" stopColor="#FAF7F0" stopOpacity="0.8" />
                <stop offset="1" stopColor="#32877A" />
              </linearGradient>
            </defs>

            {/* Ambient Blobs */}
            <rect width="1440" height="900" fill="url(#coralGlow)" />
            <rect width="1440" height="900" fill="url(#amberGlow)" />
            <rect width="1440" height="900" fill="url(#tealGlow)" />

            {/* Flowing Ribbon Shapes */}
            <path
              d="M-80 680C140 680 280 480 460 460C680 435 780 620 980 580C1180 540 1280 340 1520 320V920H-80V680Z"
              fill="url(#waveGrad1)"
              opacity="0.45"
            />
            <path
              d="M-120 480C180 460 380 690 640 640C900 590 1020 380 1320 360C1440 350 1520 400 1600 440"
              stroke="rgba(255,255,255,0.22)"
              strokeWidth="1.75"
              strokeDasharray="8 6"
            />

            {/* Connected Attack Graph Traversal Network */}
            <g opacity="0.85">
              <path
                d="M160 620 L320 530 L510 440 L690 350"
                stroke="url(#pathCoralStroke)"
                strokeWidth="3"
                strokeLinecap="round"
              />
              <path
                d="M510 440 L620 590 L810 650"
                stroke="url(#pathAmberStroke)"
                strokeWidth="2.2"
                strokeLinecap="round"
                strokeDasharray="6 4"
              />

              {/* Node 1: Entry Credential */}
              <g transform="translate(160, 620)">
                <circle r="14" fill="#FAF7F0" stroke="#E85D4A" strokeWidth="3" />
                <circle r="6" fill="#E85D4A" />
              </g>

              {/* Node 2: App Server */}
              <g transform="translate(320, 530)">
                <circle r="16" fill="#FAF7F0" stroke="#E85D4A" strokeWidth="3" />
                <rect
                  x="-6"
                  y="-6"
                  width="12"
                  height="12"
                  rx="3"
                  fill="#E85D4A"
                />
              </g>

              {/* Node 3: Lateral Pivot */}
              <g transform="translate(620, 590)">
                <circle r="15" fill="#FAF7F0" stroke="#7C5CBF" strokeWidth="3" />
                <circle r="5" fill="#7C5CBF" />
              </g>

              {/* Node 4: Critical Hop (Active Hop) */}
              <g transform="translate(510, 440)" className="node-pulse">
                <circle r="28" fill="rgba(232,93,74,0.2)" />
                <circle
                  r="19"
                  fill="#FAF7F0"
                  stroke="#E85D4A"
                  strokeWidth="3.5"
                />
                <circle r="8" fill="#E85D4A" />
              </g>

              {/* Node 5: Crown Jewel Target */}
              <g transform="translate(690, 350)">
                <circle
                  r="22"
                  fill="#FAF7F0"
                  stroke="#D99A28"
                  strokeWidth="3.5"
                />
                <circle r="10" fill="#D99A28" />
              </g>
            </g>
          </svg>
        </div>

        {/* LEFT SECTION (~56%) */}
        <div className="relative z-10 w-full lg:w-[56%] flex flex-col justify-between p-8 sm:p-12 lg:p-16 text-[#FAF7F0]">
          {/* Logo Header */}
          <div>
            <AttackPathLogo size="lg" lightText={true} />
          </div>

          {/* Central Headline */}
          <div className="my-auto py-10 lg:py-0 max-w-xl">
            <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#FAF7F0]/15 border border-white/20 backdrop-blur-md mb-6">
              <span className="w-2 h-2 rounded-full bg-[#E85D4A] animate-ping" />
              <span className="text-xs font-medium tracking-wide text-[#FAF7F0]/90 uppercase font-mono">
                Continuous Threat Exposure
              </span>
            </div>

            <h1 className="text-4xl sm:text-5xl lg:text-[56px] font-extrabold text-[#FAF7F0] leading-[1.08] tracking-tight drop-shadow-md">
              See the path.
              <br />
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-[#FAF7F0] via-[#FFE8D6] to-[#D99A28]">
                Stop the threat.
              </span>
            </h1>

            <p className="mt-5 text-base sm:text-lg text-[#FAF7F0]/85 leading-relaxed font-normal max-w-lg drop-shadow-sm">
              Discover hidden attack paths. Understand the risk. Verify every
              remediation before deployment using in-memory graph simulation.
            </p>

            <div className="mt-8 grid grid-cols-3 gap-4 pt-6 border-t border-white/15">
              <div>
                <div className="text-xl sm:text-2xl font-bold font-mono text-[#FAF7F0]">
                  11 Entities
                </div>
                <div className="text-xs text-[#FAF7F0]/70 mt-0.5">
                  Canonical Graph
                </div>
              </div>
              <div>
                <div className="text-xl sm:text-2xl font-bold font-mono text-[#D99A28]">
                  &lt; 50ms
                </div>
                <div className="text-xs text-[#FAF7F0]/70 mt-0.5">
                  Real Cypher Traversal
                </div>
              </div>
              <div>
                <div className="text-xl sm:text-2xl font-bold font-mono text-emerald-300">
                  0 Writes
                </div>
                <div className="text-xs text-[#FAF7F0]/70 mt-0.5">
                  Baseline Immutability
                </div>
              </div>
            </div>
          </div>

          {/* Footer Status Strip */}
          <div className="pt-6 border-t border-white/10 flex flex-wrap items-center justify-between gap-4 text-xs text-[#FAF7F0]/70 font-mono">
            <div className="inline-flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-400" />
              <span>FalkorDB Graph Engine Active</span>
            </div>
            <div>
              <span>Canonical Benchmark Scenario • Isolated Sandbox</span>
            </div>
          </div>
        </div>

        {/* RIGHT SECTION: Glass Authentication Panel (~44%) */}
        <div className="relative z-20 w-full lg:w-[44%] flex items-center justify-center p-6 sm:p-10 lg:p-12 lg:pl-4">
          <div className="glass-card w-full max-w-[460px] rounded-[28px] p-8 sm:p-10 transition-all duration-300">
            {/* Form Header */}
            <div className="mb-5">
              <div className="flex items-center justify-between mb-2">
                <h2 className="text-2xl sm:text-[28px] font-bold text-[#282B2A] tracking-tight font-sans">
                  Welcome back
                </h2>
                <span className="inline-flex items-center px-2.5 py-1 rounded-md text-[11px] font-mono font-medium bg-[#ECE5D8]/80 text-[#282B2A] border border-[#E3DDD2]">
                  SEC-WORKSPACE
                </span>
              </div>
              <p className="text-sm text-[#282B2A]/70">
                Sign in to your security investigation workspace.
              </p>
            </div>

            {/* Demo Notice Banner */}
            <div className="mb-4 p-2.5 rounded-lg bg-[#FAF7F0] border border-[#E3DDD2] text-[11px] text-[#686D6B] flex items-center justify-between">
              <span className="flex items-center gap-1.5">
                <Info className="w-3.5 h-3.5 text-[#32877A]" />
                <span>Frontend Demonstration Preview</span>
              </span>
              <span className="font-mono text-[10px] text-[#32877A] font-bold">RBAC NOT ENFORCED</span>
            </div>

            {/* Informational Notice for Forgot Password */}
            {showForgotNotice && (
              <div className="mb-4 p-3 rounded-xl bg-[#FAF7F0] border border-[#32877A]/30 text-xs text-[#282B2A] flex items-start justify-between gap-2 shadow-xs">
                <div className="flex flex-col gap-1.5">
                  <span className="font-semibold text-[#32877A] flex items-center gap-1">
                    <CheckCircle className="w-3.5 h-3.5" />
                    Demo Sandbox Credential Notice
                  </span>
                  <span className="text-[11px] text-[#686D6B] leading-relaxed">
                    Single Sign-On (SSO) and password resets are managed by enterprise IdP. In this synthetic sandbox, use the pre-configured SecOps profile.
                  </span>
                  <button
                    type="button"
                    onClick={handleAutofillDemo}
                    className="self-start text-[11px] font-bold text-[#E85D4A] underline hover:text-[#D44C3A] cursor-pointer mt-0.5"
                  >
                    Autofill Demo Profile (a_vance)
                  </button>
                </div>
                <button
                  type="button"
                  onClick={() => setShowForgotNotice(false)}
                  className="text-[#969B98] hover:text-[#282B2A] p-0.5 cursor-pointer"
                  title="Dismiss notice"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            )}

            {/* Validation / Authentication Error Banner */}
            {authError && (
              <div className="mb-4 p-3 rounded-xl bg-[#FDF2F0] border border-[#E85D4A]/40 text-xs text-[#E85D4A] flex flex-col gap-2">
                <div className="flex items-center gap-1.5">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>{authError}</span>
                </div>
                <button
                  type="button"
                  onClick={handleAutofillDemo}
                  className="self-start text-[11px] font-bold underline hover:text-[#D44C3A] cursor-pointer"
                >
                  Restore Demo Profile (a_vance)
                </button>
              </div>
            )}

            {/* Authentication Form */}
            <form onSubmit={handleSubmit} className="space-y-5">
              {/* Username Input */}
              <div>
                <label
                  htmlFor="username"
                  className="block text-xs font-semibold text-[#282B2A] uppercase tracking-wider mb-2"
                >
                  Security Identity / Username
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-[#282B2A]/45">
                    <User className="w-4 h-4" />
                  </div>
                  <input
                    id="username"
                    type="text"
                    value={username}
                    onChange={(e) => {
                      setUsername(e.target.value);
                      if (authError) setAuthError(null);
                    }}
                    placeholder="analyst@attackpath.internal"
                    className="glass-input w-full pl-10 pr-4 py-3 rounded-xl text-sm text-[#282B2A] font-medium placeholder:text-[#282B2A]/40"
                    required
                  />
                </div>
              </div>

              {/* Password Input */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <label
                    htmlFor="password"
                    className="block text-xs font-semibold text-[#282B2A] uppercase tracking-wider"
                  >
                    Password / Access Token
                  </label>
                  <button
                    type="button"
                    onClick={() => setShowForgotNotice(true)}
                    className="text-xs font-medium text-[#E85D4A] hover:text-[#D44C3A] transition-colors cursor-pointer"
                  >
                    Forgot password?
                  </button>
                </div>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-[#282B2A]/45">
                    <Lock className="w-4 h-4" />
                  </div>
                  <input
                    id="password"
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => {
                      setPassword(e.target.value);
                      if (authError) setAuthError(null);
                    }}
                    placeholder="Enter password"
                    className="glass-input w-full pl-10 pr-11 py-3 rounded-xl text-sm text-[#282B2A] font-medium tracking-wider placeholder:text-[#282B2A]/40"
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute inset-y-0 right-0 pr-3.5 flex items-center text-[#282B2A]/50 hover:text-[#282B2A] transition-colors cursor-pointer"
                    title={showPassword ? "Hide password" : "Show password"}
                  >
                    {showPassword ? (
                      <EyeOff className="w-4 h-4" />
                    ) : (
                      <Eye className="w-4 h-4" />
                    )}
                  </button>
                </div>
              </div>

              {/* Role Selector: Security Analyst vs Security Viewer */}
              <div>
                <label className="block text-xs font-semibold text-[#282B2A] uppercase tracking-wider mb-2">
                  Workspace Role (Demo Selector)
                </label>
                <div className="grid grid-cols-2 gap-2.5">
                  <label
                    onClick={() => setRole("analyst")}
                    className={`relative flex items-center p-3 rounded-xl cursor-pointer border glass-input transition-all ${
                      role === "analyst"
                        ? "border-[#E85D4A] bg-white shadow-sm"
                        : "hover:border-[#E85D4A]/50"
                    }`}
                  >
                    <div className="flex items-center gap-2.5 w-full">
                      <div
                        className={`w-3.5 h-3.5 rounded-full border-2 flex items-center justify-center ${
                          role === "analyst"
                            ? "border-[#E85D4A]"
                            : "border-[#D1C9BE]"
                        }`}
                      >
                        {role === "analyst" && (
                          <div className="w-1.5 h-1.5 rounded-full bg-[#E85D4A]" />
                        )}
                      </div>
                      <div>
                        <div className="text-xs font-semibold text-[#282B2A] leading-none">
                          Security Analyst
                        </div>
                        <div className="text-[10px] text-[#282B2A]/60 mt-0.5">
                          Simulate &amp; Remediate
                        </div>
                      </div>
                    </div>
                  </label>

                  <label
                    onClick={() => setRole("viewer")}
                    className={`relative flex items-center p-3 rounded-xl cursor-pointer border glass-input transition-all ${
                      role === "viewer"
                        ? "border-[#E85D4A] bg-white shadow-sm"
                        : "hover:border-[#E85D4A]/50"
                    }`}
                  >
                    <div className="flex items-center gap-2.5 w-full">
                      <div
                        className={`w-3.5 h-3.5 rounded-full border-2 flex items-center justify-center ${
                          role === "viewer"
                            ? "border-[#E85D4A]"
                            : "border-[#D1C9BE]"
                        }`}
                      >
                        {role === "viewer" && (
                          <div className="w-1.5 h-1.5 rounded-full bg-[#E85D4A]" />
                        )}
                      </div>
                      <div>
                        <div className="text-xs font-semibold text-[#282B2A] leading-none">
                          Security Viewer
                        </div>
                        <div className="text-[10px] text-[#282B2A]/60 mt-0.5">
                          Read-Only Audit
                        </div>
                      </div>
                    </div>
                  </label>
                </div>
              </div>

              {/* Submit Button */}
              <div className="pt-2">
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="w-full py-3.5 px-6 rounded-xl font-semibold text-sm text-white bg-gradient-to-r from-[#E85D4A] via-[#EB6856] to-[#D99A28] hover:from-[#D44C3A] hover:to-[#C88A20] shadow-[0_8px_20px_-4px_rgba(232,93,74,0.4)] hover:shadow-[0_12px_24px_-4px_rgba(232,93,74,0.5)] transition-all duration-200 transform hover:-translate-y-0.5 active:translate-y-0 flex items-center justify-center gap-2 disabled:opacity-75 cursor-pointer"
                >
                  {isSubmitting ? (
                    <>
                      <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                      <span>Entering Workspace...</span>
                    </>
                  ) : (
                    <>
                      <span>Sign in</span>
                      <ArrowRight className="w-4 h-4" />
                    </>
                  )}
                </button>
              </div>
            </form>

            {/* Disclaimer & Synthetic Data Notice */}
            <div className="mt-6 pt-5 border-t border-[#E3DDD2]/80">
              <div className="flex items-center justify-between text-xs text-[#282B2A]/65">
                <span className="inline-flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-[#E85D4A]" />
                  <span>Frontend Demo Preview</span>
                </span>
                <span className="font-mono text-[11px] text-[#282B2A]/50">
                  Client Session
                </span>
              </div>
              <div className="mt-2 text-[11px] text-[#282B2A]/60 leading-normal bg-[#FAF7F0]/60 p-2.5 rounded-lg border border-[#E3DDD2]/50">
                <span className="font-semibold text-[#282B2A]">Notice:</span> Server-side authentication and backend RBAC are not enforced in this preview build; role selection demonstrates UI perspective only. Pre-loaded with SecOps profile (
                <code className="font-mono text-[#282B2A] font-semibold">
                  a_vance
                </code>
                ) for instant access to the{" "}
                <span className="font-medium text-[#E85D4A]">
                  INV-2025-084
                </span>{" "}
                investigation workspace.
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}

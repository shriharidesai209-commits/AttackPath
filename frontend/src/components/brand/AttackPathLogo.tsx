import React from "react";

interface AttackPathLogoProps {
  size?: "sm" | "md" | "lg";
  showSubtitle?: boolean;
  lightText?: boolean;
}

export function AttackPathLogo({
  size = "md",
  showSubtitle = true,
  lightText = false,
}: AttackPathLogoProps) {
  const iconSizes = {
    sm: "w-7 h-7",
    md: "w-9 h-9",
    lg: "w-12 h-12",
  };

  const textSizes = {
    sm: "text-[18px]",
    md: "text-[22px]",
    lg: "text-[30px]",
  };

  const subSizes = {
    sm: "text-[7px]",
    md: "text-[8.5px]",
    lg: "text-[10px]",
  };

  return (
    <div className="inline-flex items-center gap-3 select-none">
      <div
        className={`relative shrink-0 flex items-center justify-center ${iconSizes[size]}`}
      >
        <svg
          viewBox="0 0 100 100"
          className="w-full h-full overflow-visible"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <defs>
            <linearGradient
              id="apRibbonMain"
              x1="15"
              y1="85"
              x2="85"
              y2="85"
              gradientUnits="userSpaceOnUse"
            >
              <stop offset="0%" stopColor="#D93829" />
              <stop offset="35%" stopColor="#E85D4A" />
              <stop offset="65%" stopColor="#F07D48" />
              <stop offset="100%" stopColor="#8A2016" />
            </linearGradient>
            <linearGradient
              id="apRibbonInner"
              x1="30"
              y1="25"
              x2="70"
              y2="90"
              gradientUnits="userSpaceOnUse"
            >
              <stop offset="0%" stopColor="#FFFFFF" stopOpacity="0.6" />
              <stop offset="40%" stopColor="#E85D4A" />
              <stop offset="100%" stopColor="#42100C" />
            </linearGradient>
            <linearGradient
              id="apOrbitGrad"
              x1="10"
              y1="80"
              x2="90"
              y2="20"
              gradientUnits="userSpaceOnUse"
            >
              <stop offset="0%" stopColor="#E8A048" stopOpacity="0.4" />
              <stop offset="50%" stopColor="#FAF7F0" stopOpacity="0.85" />
              <stop offset="100%" stopColor="#E85D4A" stopOpacity="0.9" />
            </linearGradient>
            <radialGradient id="apSphereTeal" cx="35%" cy="35%" r="65%">
              <stop offset="0%" stopColor="#5FE3CD" />
              <stop offset="60%" stopColor="#2B8175" />
              <stop offset="100%" stopColor="#11453E" />
            </radialGradient>
            <radialGradient id="apSphereOrange" cx="35%" cy="35%" r="65%">
              <stop offset="0%" stopColor="#FFAA5C" />
              <stop offset="70%" stopColor="#E85D4A" />
              <stop offset="100%" stopColor="#8A1B0E" />
            </radialGradient>
            <radialGradient id="apSphereAmber" cx="35%" cy="35%" r="65%">
              <stop offset="0%" stopColor="#FFDF88" />
              <stop offset="70%" stopColor="#E5962B" />
              <stop offset="100%" stopColor="#8C4F00" />
            </radialGradient>
          </defs>

          {/* Orbiting Connector Arcs */}
          <path
            d="M18 76 C 14 52, 28 26, 68 18"
            stroke="url(#apOrbitGrad)"
            strokeWidth="2.2"
            strokeLinecap="round"
            fill="none"
          />
          <path
            d="M68 18 L76 33"
            stroke="#E85D4A"
            strokeWidth="2"
            strokeLinecap="round"
            fill="none"
          />

          {/* Back dynamic ribbon sweep */}
          <path
            d="M16 75 C 25 72, 38 60, 48 30 C 51 21, 55 21, 58 30 C 68 60, 78 78, 86 86 C 82 87, 72 82, 65 70 L 52 48 C 45 64, 34 77, 16 75 Z"
            fill="url(#apRibbonInner)"
            opacity="0.95"
          />

          {/* Front Primary Sweeping 'A' Arch */}
          <path
            d="M15 76 C 12 79, 14 84, 21 84 C 36 84, 46 68, 52 56 C 58 44, 66 60, 78 84 C 83 87, 88 85, 87 81 C 82 66, 64 28, 55 18 C 51 13, 47 13, 43 20 C 32 38, 18 64, 15 76 Z"
            fill="url(#apRibbonMain)"
          />
          <path
            d="M20 83 C 32 83, 43 72, 53 58 C 44 65, 33 72, 20 83 Z"
            fill="#FFF5EA"
            opacity="0.4"
          />

          {/* Central 4-Point Star / Spark Reflection inside Arch */}
          <path
            d="M53 36 Q 53 41, 48 41 Q 53 41, 53 46 Q 53 41, 58 41 Q 53 41, 53 36 Z"
            fill="#FFFFFF"
            opacity="0.95"
          />

          {/* Orbiting Network Spheres / Graph Nodes */}
          <circle
            cx="16"
            cy="75"
            r="5.5"
            fill="url(#apSphereAmber)"
            stroke="#FFFFFF"
            strokeWidth="1.5"
          />
          <circle
            cx="24"
            cy="43"
            r="6"
            fill="url(#apSphereTeal)"
            stroke="#FFFFFF"
            strokeWidth="1.5"
          />
          <circle
            cx="77"
            cy="19"
            r="7"
            fill="url(#apSphereOrange)"
            stroke="#FFFFFF"
            strokeWidth="1.5"
          />
          <circle
            cx="77"
            cy="19"
            r="10"
            stroke="#FAF7F0"
            strokeWidth="1"
            strokeOpacity="0.6"
            strokeDasharray="2 2"
            fill="none"
          />
        </svg>
      </div>

      <div className="flex flex-col justify-center min-w-0">
        <div
          className={`flex items-baseline leading-none tracking-tight font-bold font-sans ${textSizes[size]}`}
        >
          <span
            className={
              lightText
                ? "text-white"
                : "text-[#282B2A]"
            }
          >
            Attack
          </span>
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-[#E85D4A] via-[#F26A54] to-[#F18D45]">
            Path
          </span>
        </div>
        {showSubtitle && (
          <span
            className={`font-mono font-semibold uppercase tracking-[0.16em] mt-1 leading-none ${
              lightText ? "text-[#FAF7F0]/80" : "text-[#686D6B]"
            } ${subSizes[size]}`}
          >
            GRAPH-POWERED SECURITY INVESTIGATION
          </span>
        )}
      </div>
    </div>
  );
}

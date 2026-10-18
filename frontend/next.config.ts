import type { NextConfig } from "next";

// Deployment-safe backend URL:
// In production on Vercel, set BACKEND_URL to your Render Web Service URL (e.g. https://attackpath-api.onrender.com).
// In local development, defaults safely to http://127.0.0.1:8000.
const BACKEND_URL = (process.env.BACKEND_URL || "http://127.0.0.1:8000").replace(/\/$/, "");

const nextConfig: NextConfig = {
  /* config options here */
  cacheComponents: true,
  partialPrefetching: true,
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
  async rewrites() {
    return [
      {
        source: "/api/v1/:path*",
        destination: `${BACKEND_URL}/api/v1/:path*`,
      },
      {
        source: "/health/:path*",
        destination: `${BACKEND_URL}/health/:path*`,
      },
      {
        source: "/health",
        destination: `${BACKEND_URL}/health`,
      },
    ];
  },
};

export default nextConfig;

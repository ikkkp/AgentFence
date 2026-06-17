import type { NextConfig } from "next";

const rawBasePath = process.env.NEXT_PUBLIC_BASE_PATH ?? "";
const basePath =
  rawBasePath && rawBasePath !== "/" ? rawBasePath.replace(/\/$/, "") : "";
const isGitHubPages = process.env.GITHUB_PAGES === "true";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  transpilePackages: ["@agentfence/types"],
  ...(isGitHubPages
    ? {
        output: "export" as const,
        trailingSlash: true,
        ...(basePath ? { basePath, assetPrefix: basePath } : {}),
        images: {
          unoptimized: true
        }
      }
    : {})
};

export default nextConfig;

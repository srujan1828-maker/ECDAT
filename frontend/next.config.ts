import type { NextConfig } from "next";

// API forwarding is implemented by src/app/api/[...path]/route.ts so runtime
// environment variables, authentication, upload limits, and normalized error
// responses work identically in development, production, and containers.
const nextConfig: NextConfig = {};

export default nextConfig;

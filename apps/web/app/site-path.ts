const basePath = process.env.NEXT_PUBLIC_BASE_PATH?.replace(/\/$/, "") ?? "";

export function sitePath(path: string): string {
  if (!path.startsWith("/")) {
    return path;
  }
  if (!basePath) {
    return path;
  }
  return path === "/" ? `${basePath}/` : `${basePath}${path}`;
}

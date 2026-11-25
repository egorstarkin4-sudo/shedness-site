import esbuild from "esbuild";

const entries = [
  "src-ts/effects.ts",
  "src-ts/animations.ts",
  "src-ts/landing.ts",
  "src-ts/profile.ts",
  "src-ts/reset.ts",
  "src-ts/admin.ts",
];

await esbuild.build({
  entryPoints: entries,
  outdir: "assets/js",
  bundle: true,
  format: "iife",
  platform: "browser",
  target: ["es2020"],
  minify: true,
  sourcemap: false,
  define: {
    "process.env.NODE_ENV": '"production"',
  },
});

console.log("Built assets/js bundles successfully.");

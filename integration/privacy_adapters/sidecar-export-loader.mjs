/** Node loader used only by swiyu-zkid.mjs to reach sidecar-node's bundled classes. */
export async function load(url, context, nextLoad) {
  const result = await nextLoad(url, context);
  if (!url.endsWith("/dist/swiyu-zkp/sidecar-node.js")) return result;
  const source = result.source?.toString?.();
  if (!source) return result;
  const needle =
    "export { loadSwiyuSidecarFromConfigFile, provisionSwiyuAuthoritativeStatusSnapshotFromFile, startSwiyuSidecarServer };";
  if (!source.includes(needle)) return result;
  return {
    format: "module",
    shortCircuit: true,
    source: source.replace(
      needle,
      "export { loadSwiyuSidecarFromConfigFile, provisionSwiyuAuthoritativeStatusSnapshotFromFile, startSwiyuSidecarServer, SwiyuVerifierSidecarService, SwiyuZkpVerifier };",
    ),
  };
}

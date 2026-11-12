import type { RunConfig, SignalSource } from "../contracts/index.js";
import type { TriageProvider } from "../l2/index.js";
import { createAorSource } from "./aor.js";
import { createCrgTriage } from "./crg.js";
import { createRegistrySource, type RegistryFetch } from "./registry.js";
import { createSemgrepSource, type CommandRunner } from "./semgrep.js";

export interface SourceFactoryOptions {
  root: string;
  runner?: CommandRunner;
  fetchImpl?: RegistryFetch;
  python?: string;
}

export function createSources(config: RunConfig, opts: SourceFactoryOptions): SignalSource[] {
  const sources: SignalSource[] = [];
  if (config.sources.semgrep.enabled) sources.push(createSemgrepSource(config, opts));
  if (config.sources.aor.enabled) sources.push(createAorSource(config, opts));
  if (config.sources.registry.enabled) sources.push(createRegistrySource(config, opts));
  return sources;
}

export function createTriage(config: RunConfig, opts: SourceFactoryOptions): TriageProvider | null {
  if (!config.triage.enabled || !config.sources.crg.enabled) return null;
  return createCrgTriage(config, opts);
}

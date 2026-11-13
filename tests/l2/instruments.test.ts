import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { RunConfig } from "../../src/contracts/index.js";
import { parseConfig } from "../../src/config/index.js";
import {
  declaredInstruments,
  instrumentFor,
  parseAorProbe,
  parseOcrVersion,
  parseSemgrepVersion,
} from "../../src/l2/instruments.js";
import { review } from "../../src/l2/index.js";
import type { ChangeEvent } from "../../src/contracts/index.js";

const config = (mode: "live" | "replay" = "replay"): RunConfig => {
  const parsed = parseConfig(JSON.parse(readFileSync("configs/b4g.json", "utf8")) as unknown);
  return { ...parsed, mode };
};

const change: ChangeEvent = {
  id: "evt",
  sessionId: "sess",
  rootCallId: "call",
  phase: "post",
  trigger: "write",
  files: ["src/demo/app.py"],
  diff: null,
  diffProvenance: "observed",
  ts: 1,
};

describe("instrument identity", () => {
  it("reads the build commit, not the release tag, out of `ocr --version`", () => {
    // v1.13.7 was tagged at b1dcffb, so a release-number match would accept the
    // wrong binary; the parenthesised commit is the pin the config carries.
    const parsed = parseOcrVersion("open-code-review v1.13.7 (b1dcffb) windows/amd64");
    expect(parsed.version).toBe("v1.13.7");
    expect(parsed.commit).toBe("b1dcffb");
  });

  it("parses a bare semgrep version and keeps a commit when one is printed", () => {
    expect(parseSemgrepVersion("1.184.0")).toEqual({ version: "1.184.0", commit: null });
    expect(parseSemgrepVersion("1.184.0\ncommit 0ddd1f5b")).toEqual({
      version: "1.184.0",
      commit: "0ddd1f5b",
    });
  });

  it("marks a replay run as declared, so its rows cannot stand in for a live one", async () => {
    const instrument = await instrumentFor(config("replay"), () => {
      throw new Error("replay must not spawn a probe");
    });
    expect(instrument.semgrep.source).toBe("declared");
    expect(instrument.ocr.source).toBe("declared");
    expect(instrument.ocr.commit).toBe(declaredInstruments(config("replay")).ocr.commit);
  });

  it("records what answered --version in a live row", async () => {
    const outcome = await review(change, {
      runId: "run-1",
      config: config("live"),
      sources: [],
      artifact: null,
      instrument: {
        semgrep: { name: "semgrep", version: "9.9.9", commit: null, source: "observed" },
        ocr: { name: "ocr", version: "v9.9.9", commit: "deadbee", source: "observed" },
        aor_model: {
          provider: "deepseek",
          id: "deepseek-flash",
          params: { url: "https://api.deepseek.com", configured: "deepseek-chat" },
          source: "observed",
        },
      },
    });
    expect(outcome.row.instrument.semgrep.version).toBe("9.9.9");
    expect(outcome.row.instrument.ocr.commit).toBe("deadbee");
    // The model is the deepest instrument: without it a row cannot say what
    // actually wrote its AOR findings.
    expect(outcome.row.instrument.aor_model.id).toBe("deepseek-flash");
    // The declaration stays beside it: a reader can see the two disagree.
    expect(outcome.row.toolchain.semgrep).not.toBe(outcome.row.instrument.semgrep.version);
  });

  it("reads the served model out of `ocr llm test`, not the configured one", () => {
    // `deepseek-chat` was requested; the service answered `deepseek-flash`. The
    // answer is the ruler, and the probe is the only place it is printed.
    const parsed = parseAorProbe(
      [
        "Source: provider:deepseek",
        "URL:    https://api.deepseek.com",
        "Model:  deepseek-flash",
        "I am open-code-review, a code review assistant.",
        "\u2713 Connection test successful",
        "\u2713 Tool-call round trip verified",
      ].join("\n"),
    );
    expect(parsed).toEqual({
      provider: "deepseek",
      url: "https://api.deepseek.com",
      served: "deepseek-flash",
      roundTrip: true,
    });
  });

  it("does not claim a round trip when the probe did not report one", () => {
    const parsed = parseAorProbe("Error: llm request failed: 401 unauthorized");
    expect(parsed.served).toBeNull();
    expect(parsed.roundTrip).toBe(false);
  });
});

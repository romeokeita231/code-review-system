import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { ChangeEvent } from "@contracts";
import { describe, expect, it } from "vitest";
import { DshAdapter, type HostApi, type PostExecuteArgs, type PreExecuteArgs } from "@l1";

interface Fixture {
  disk: string | null;
  pre: PreExecuteArgs;
  post: PostExecuteArgs;
}

function load(name: string): Fixture {
  const path = fileURLToPath(new URL(`../fixtures/l1/${name}`, import.meta.url));
  return JSON.parse(readFileSync(path, "utf8")) as Fixture;
}

interface FakeApi extends HostApi {
  reads: string[];
}

function makeApi(cwd: string, disk: string | null): FakeApi {
  const reads: string[] = [];
  return {
    reads,
    cwd: () => cwd,
    readFile: async (path: string) => {
      reads.push(path);
      if (disk === null) throw new Error("ENOENT");
      return disk;
    },
  };
}

describe("DshAdapter pre-execute", () => {
  it("synthesizes a pre event for write", async () => {
    const fixture = load("write.json");
    const api = makeApi("F:\\repo", fixture.disk);
    const adapter = new DshAdapter({ ...api, clock: () => 999 }, () => "generated");
    const result = await adapter.preExecute(fixture.pre);

    expect(result.kind).toBe("allow");
    if (result.kind !== "allow" || result.event === null) throw new Error("expected event");
    expect(ChangeEvent.parse(result.event)).toEqual(result.event);
    expect(result.event.id).toBe("call-write-1");
    expect(result.event.phase).toBe("pre");
    expect(result.event.diffProvenance).toBe("synthesized");
    expect(result.event.files).toEqual(["src/app.ts"]);
    expect(result.event.ts).toBe(1700000000000);
    expect(result.event.diff).toContain("-const b = 2;");
    expect(result.event.diff).toContain("+const b = 3;");
    expect(api.reads[0]?.replace(/\\/g, "/")).toBe("F:/repo/src/app.ts");
  });

  it("uses an empty before value when the write target does not exist", async () => {
    const fixture = load("write.json");
    const adapter = new DshAdapter(makeApi("F:\\repo", null), () => "generated");
    const result = await adapter.preExecute({
      ...fixture.pre,
      arguments: { file_path: "src/new.ts", content: "hello\n" },
    });

    if (result.kind !== "allow" || result.event === null) throw new Error("expected event");
    expect(result.event.diff).toBe("--- a/src/new.ts\n+++ b/src/new.ts\n@@ -1,0 +1,1 @@\n+hello");
  });

  it("applies edit with LF normalization", async () => {
    const fixture = load("edit-crlf.json");
    const adapter = new DshAdapter(makeApi("F:\\repo", fixture.disk), () => "generated");
    const result = await adapter.preExecute(fixture.pre);

    if (result.kind !== "allow" || result.event === null) throw new Error("expected event");
    expect(result.event.trigger).toBe("edit");
    expect(result.event.diff).toContain("-second line");
    expect(result.event.diff).toContain("+patched line");
    expect(result.event.diff).not.toContain("\\r");
  });

  it("denies an ambiguous edit with the recorded hook shape", async () => {
    const fixture = load("edit-ambiguous.json");
    const adapter = new DshAdapter(makeApi("F:\\repo", fixture.disk), () => "generated");

    await expect(adapter.preExecute(fixture.pre)).resolves.toEqual({
      kind: "deny",
      reason: "old_string appears 2 times in src/app.ts",
    });
  });

  it("skips writes outside the repo root without reading", async () => {
    const fixture = load("write.json");
    const api = makeApi("F:\\repo", fixture.disk);
    const adapter = new DshAdapter(api, () => "generated");
    const result = await adapter.preExecute({
      ...fixture.pre,
      arguments: { file_path: "F:\\elsewhere\\app.ts", content: "x\n" },
    });

    expect(result).toEqual({ kind: "allow", event: null, sourceText: {} });
    expect(api.reads).toEqual([]);
  });
});

describe("DshAdapter post-execute", () => {
  it("emits an observed post event from value before/after", async () => {
    const fixture = load("write.json");
    const adapter = new DshAdapter(makeApi("F:\\repo", fixture.disk), () => "generated");
    const { event, sourceText } = await adapter.postExecute(fixture.post);

    expect(ChangeEvent.parse(event)).toEqual(event);
    expect(event.id).toBe("call-write-1");
    expect(event.phase).toBe("post");
    expect(event.diffProvenance).toBe("observed");
    expect(event.files).toEqual(["src/app.ts"]);
    expect(event.diff).toContain("+const b = 3;");
    expect(sourceText["src/app.ts"]).toContain("const b = 3;");
  });

  it("emits a post-only command event for non-file tools", async () => {
    const fixture = load("command.json");
    const adapter = new DshAdapter(makeApi("F:\\repo", ""), () => "generated");
    const { event } = await adapter.postExecute(fixture.post);

    expect(ChangeEvent.parse(event)).toEqual(event);
    expect(event.trigger).toBe("command");
    expect(event.files).toBeNull();
    expect(event.diff).toBeNull();
    expect(event.diffProvenance).toBe("none");
  });
});

describe("DshAdapter preDecision", () => {
  it("maps verdicts and events to the host response shape", async () => {
    const fixture = load("write.json");
    const adapter = new DshAdapter(makeApi("F:\\repo", fixture.disk), () => "generated");
    const result = await adapter.preExecute(fixture.pre);

    expect(adapter.preDecision({ decision: "deny", reason: "blocked" })).toEqual({
      decision: "deny",
      reason: "blocked",
    });
    expect(adapter.preDecision({ decision: "allow" })).toEqual({ decision: "allow" });
    if (result.kind === "allow" && result.event !== null) {
      expect(adapter.preDecision(result.event)).toEqual({ decision: "allow" });
    }
  });
});

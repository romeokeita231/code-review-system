import { ChangeEvent } from "@contracts";
import { describe, expect, it } from "vitest";
import { commandEvent, noChange, observePostEvent, synthesizePreEvent, toRepoRelative } from "@l1";

describe("toRepoRelative", () => {
  it("returns a POSIX repo-relative path for absolute Windows paths", () => {
    expect(toRepoRelative("F:\\repo", "F:\\repo\\src\\app.ts")).toBe("src/app.ts");
    expect(toRepoRelative("F:/repo/", "F:/repo/src/deep/file.ts")).toBe("src/deep/file.ts");
    expect(toRepoRelative("F:\\repo", "src/app.ts")).toBe("src/app.ts");
  });

  it("rejects paths outside the root", () => {
    expect(() => toRepoRelative("F:\\repo", "F:\\other\\app.ts")).toThrow();
    expect(() => toRepoRelative("F:\\repo", "..\\..\\escape.ts")).toThrow();
  });
});

describe("change events", () => {
  it("synthesizes pre events with one diff line per changed line", () => {
    const event = synthesizePreEvent({
      id: "call-1",
      sessionId: "session-1",
      rootCallId: "root-1",
      trigger: "edit",
      files: [{ path: "src/app.ts", before: "a\nb\n", after: "a\nc\n" }],
      ts: 1,
    });
    expect(ChangeEvent.parse(event)).toEqual(event);
    expect(event.phase).toBe("pre");
    expect(event.diffProvenance).toBe("synthesized");
    expect(event.files).toEqual(["src/app.ts"]);
    expect(event.diff).toBe("--- a/src/app.ts\n+++ b/src/app.ts\n@@ -2,1 +2,1 @@\n-b\n+c");
  });

  it("builds observed post events", () => {
    const event = observePostEvent({
      id: "call-1",
      sessionId: "session-1",
      rootCallId: "root-1",
      trigger: "write",
      path: "src/app.ts",
      before: "old\n",
      after: "new\n",
      ts: 2,
    });
    expect(ChangeEvent.parse(event)).toEqual(event);
    expect(event.phase).toBe("post");
    expect(event.diffProvenance).toBe("observed");
    expect(event.diff).toBe("--- a/src/app.ts\n+++ b/src/app.ts\n@@ -1,1 +1,1 @@\n-old\n+new");
  });

  it("emits post-only command events without files or diff", () => {
    const event = commandEvent({ id: "call-2", sessionId: "session-1", rootCallId: "root-1", ts: 3 });
    expect(ChangeEvent.parse(event)).toEqual(event);
    expect(event.phase).toBe("post");
    expect(event.trigger).toBe("command");
    expect(event.files).toBeNull();
    expect(event.diff).toBeNull();
    expect(event.diffProvenance).toBe("none");
  });
});

describe("noChange", () => {
  it("compares LF-normalized text", () => {
    expect(noChange("a\r\nb\r\n", "a\nb\n")).toBe(true);
    expect(noChange("a\r\nb\r\n", "a\nc\n")).toBe(false);
    expect(noChange(null, "")).toBe(false);
  });
});

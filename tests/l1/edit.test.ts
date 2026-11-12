import { describe, expect, it } from "vitest";
import { applyEdit, hashPair, normalizeLf, sha256Text, type EditArgs } from "@l1";

const base: EditArgs = {
  file_path: "src/app.ts",
  old_string: "",
  new_string: "",
  replace_all: false,
};

describe("normalizeLf", () => {
  it("converts CRLF and lone CR to LF", () => {
    expect(normalizeLf("a\r\nb\rc\nd")).toBe("a\nb\nc\nd");
  });
});

describe("applyEdit", () => {
  it("matches across CRLF and LF and returns LF-normalized content", () => {
    const result = applyEdit("const a = 1;\r\nconst b = 2;\r\n", {
      ...base,
      old_string: "const b = 2;",
      new_string: "const b = 3;",
    });
    expect(result).toEqual({ content: "const a = 1;\nconst b = 3;\n" });
  });

  it("reports zero hits", () => {
    expect(applyEdit("a\n", { ...base, old_string: "zzz", new_string: "y" })).toEqual({
      error: "old_string not found in src/app.ts",
    });
  });

  it("rejects ambiguous matches without replace_all", () => {
    expect(applyEdit("x\nx\n", { ...base, old_string: "x", new_string: "y", replace_all: false })).toEqual({
      error: "old_string appears 2 times in src/app.ts",
    });
  });

  it("replaces every occurrence with replace_all", () => {
    expect(applyEdit("x\nx\n", { ...base, old_string: "x", new_string: "y", replace_all: true })).toEqual({
      content: "y\ny\n",
    });
  });

  it("rejects an empty old_string", () => {
    const result = applyEdit("a", { ...base, old_string: "", new_string: "b" });
    expect("error" in result).toBe(true);
  });

  it("counts non-overlapping occurrences only", () => {
    expect(applyEdit("aaa", { ...base, old_string: "aa", new_string: "b" })).toEqual({ content: "ba" });
  });
});

describe("sha256", () => {
  it("is stable across CRLF and LF", () => {
    expect(sha256Text("a\r\nb\r\n")).toBe(sha256Text("a\nb\n"));
  });

  it("hashes the LF-normalized pair", () => {
    const pair = hashPair("a\r\n", "a\n");
    expect(pair.old_sha256).toBe(pair.new_sha256);
    expect(pair.new_sha256).toBe(sha256Text("a\n"));
    expect(hashPair(null, "a").old_sha256).toBeNull();
  });
});

import { describe, expect, it } from "vitest";

import { assertVersionTracksPopulation } from "../../scripts/build-ds2.js";

const rootA = "a".repeat(64);
const rootB = "b".repeat(64);

describe("manifest version tracks the population", () => {
  it("accepts a first write (no committed manifest)", () => {
    expect(() => assertVersionTracksPopulation(null, { version: "ds-2.0.0", content_sha256_root: rootA })).not.toThrow();
  });

  it("accepts an unchanged population under the same version", () => {
    expect(() =>
      assertVersionTracksPopulation(
        { version: "ds-2.0.0", content_sha256_root: rootA },
        { version: "ds-2.0.0", content_sha256_root: rootA },
      ),
    ).not.toThrow();
  });

  it("accepts a changed population under a bumped version", () => {
    expect(() =>
      assertVersionTracksPopulation(
        { version: "ds-2.0.0", content_sha256_root: rootA },
        { version: "ds-2.1.0", content_sha256_root: rootB },
      ),
    ).not.toThrow();
  });

  it("rejects a changed population under an unchanged version", () => {
    expect(() =>
      assertVersionTracksPopulation(
        { version: "ds-2.0.0", content_sha256_root: rootA },
        { version: "ds-2.0.0", content_sha256_root: rootB },
      ),
    ).toThrow(/unchanged manifest version \(ds-2\.0\.0\)/);
  });
});

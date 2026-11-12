import { createHash } from "node:crypto";

export interface EditArgs {
  file_path: string;
  old_string: string;
  new_string: string;
  replace_all?: boolean;
}

export type EditResult = { content: string } | { error: string };

export interface HashPair {
  old_sha256: string | null;
  new_sha256: string;
}

export function normalizeLf(text: string): string {
  return text.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
}

function countOccurrences(text: string, needle: string): number {
  let count = 0;
  let index = text.indexOf(needle);
  while (index !== -1) {
    count += 1;
    index = text.indexOf(needle, index + needle.length);
  }
  return count;
}

export function applyEdit(content: string, args: EditArgs): EditResult {
  const text = normalizeLf(content);
  const oldText = normalizeLf(args.old_string);
  const newText = normalizeLf(args.new_string);

  if (oldText.length === 0) {
    return { error: `old_string must not be empty in ${args.file_path}` };
  }

  const count = countOccurrences(text, oldText);
  if (count === 0) {
    return { error: `old_string not found in ${args.file_path}` };
  }
  if (count > 1 && args.replace_all !== true) {
    return { error: `old_string appears ${count} times in ${args.file_path}` };
  }

  return { content: text.split(oldText).join(newText) };
}

export function sha256Text(text: string): string {
  return createHash("sha256").update(normalizeLf(text), "utf8").digest("hex");
}

export function hashPair(before: string | null, after: string): HashPair {
  return {
    old_sha256: before === null ? null : sha256Text(before),
    new_sha256: sha256Text(after),
  };
}

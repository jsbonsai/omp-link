import { test, describe } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import extension from "../../index.js";

// The two shipped skills are one document with two front matters: `package.json` points Pi at
// `./skills`, and both directories are loaded into agents. They have already drifted once, and
// both copies then described a capability that did not exist — an agent following shipped
// instructions was told a guard would stop a destructive command that nothing stops.
//
// These are the two properties that make that class of drift a test failure instead of a
// user-visible lie: the bodies below the front matter are byte-identical, and every tool the
// body names is a tool the extension actually registers (and vice versa).

const SKILLS_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "skills");
const CANONICAL = "omp-link-coordination";
const MIRROR = "pi-link-coordination";

function readSkill(dirName) {
  const file = path.join(SKILLS_DIR, dirName, "SKILL.md");
  const raw = fs.readFileSync(file, "utf8");
  const match = /^---\n([\s\S]*?)\n---\n/.exec(raw);
  assert.ok(match, `${dirName}/SKILL.md has no YAML front matter`);
  return { file, frontMatter: match[1], body: raw.slice(match[0].length) };
}

/** Tool names the extension registers, collected from a fake host. One load per process. */
function registeredToolNames() {
  const names = [];
  extension({
    registerFlag() {},
    getFlag() {
      return undefined;
    },
    registerTool(spec) {
      names.push(spec.name);
    },
    registerCommand() {},
    registerMessageRenderer() {},
    sendMessage() {},
    on() {},
  });
  return names;
}

describe("REGRESSION: the two shipped SKILL.md files cannot drift apart or invent a tool", () => {
  test("each skill declares the name of the directory it ships in", () => {
    for (const dirName of [CANONICAL, MIRROR]) {
      const { frontMatter } = readSkill(dirName);
      const declared = /^name:\s*(\S+)\s*$/m.exec(frontMatter);
      assert.ok(declared, `${dirName}/SKILL.md front matter declares no name`);
      assert.strictEqual(
        declared[1],
        dirName,
        `${dirName}/SKILL.md declares name "${declared[1]}"; a copied front matter registers the same skill twice`,
      );
    }
  });

  test("the bodies below the front matter are identical", () => {
    const canonical = readSkill(CANONICAL);
    const mirror = readSkill(MIRROR);

    if (canonical.body !== mirror.body) {
      const a = canonical.body.split("\n");
      const b = mirror.body.split("\n");
      let line = 0;
      while (line < a.length && line < b.length && a[line] === b[line]) line++;
      assert.fail(
        `skills/${CANONICAL}/SKILL.md and skills/${MIRROR}/SKILL.md diverge at body line ${line + 1}:\n`
        + `  ${CANONICAL}: ${JSON.stringify(a[line] ?? "<end of file>")}\n`
        + `  ${MIRROR}: ${JSON.stringify(b[line] ?? "<end of file>")}\n`
        + `${CANONICAL} is canonical: copy its body under the mirror's own front matter.`,
      );
    }
  });

  test("every tool the skill names is registered, and every registered tool is documented", () => {
    const { body } = readSkill(CANONICAL);
    const registered = registeredToolNames();
    assert.ok(registered.length > 0, "the extension registered no tools");

    const named = [...new Set(body.match(/link_[a-z_]+/g) || [])].sort();
    const invented = named.filter((name) => !registered.includes(name));
    assert.deepStrictEqual(
      invented,
      [],
      `SKILL.md documents tool(s) the extension does not register: ${invented.join(", ")}`,
    );

    const undocumented = registered.filter((name) => !named.includes(name)).sort();
    assert.deepStrictEqual(
      undocumented,
      [],
      `the extension registers tool(s) SKILL.md never mentions: ${undocumented.join(", ")}`,
    );
  });
});

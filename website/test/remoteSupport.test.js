import test from "node:test";
import assert from "node:assert/strict";
import { hashPassword, normalizeRemoteMode, verifyPassword } from "../remoteSupport.js";

test("senhas administrativas usam hash com salt e comparação segura", () => {
  const first = hashPassword("uma-senha-longa-e-segura");
  const second = hashPassword("uma-senha-longa-e-segura");
  assert.notEqual(first.salt, second.salt);
  assert.notEqual(first.hash, second.hash);
  assert.equal(verifyPassword("uma-senha-longa-e-segura", first.salt, first.hash), true);
  assert.equal(verifyPassword("senha-incorreta", first.salt, first.hash), false);
});

test("somente os dois modos explícitos de suporte são aceitos", () => {
  assert.equal(normalizeRemoteMode("view"), "view");
  assert.equal(normalizeRemoteMode("control"), "control");
  assert.equal(normalizeRemoteMode("unattended"), null);
  assert.equal(normalizeRemoteMode(""), null);
});

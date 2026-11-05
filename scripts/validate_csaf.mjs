#!/usr/bin/env node
// validate_csaf.mjs: validate CSAF 2.0 documents against the JSON schema and
// all mandatory tests (CSAF 2.0 §6.1), entirely in-process.
//
// No validator service, no localhost port and no network calls: this uses the
// same engine as the Secvisogram validator service
// (@secvisogram/csaf-validator-lib, pinned in package-lock.json), loaded from
// node_modules. Run `npm ci` once, then it works offline.
//
// Usage:   node scripts/validate_csaf.mjs file.json [more.json ...]
//          npm run validate -- file.json
// Exit:    0 all valid, 1 at least one invalid/unreadable file, 2 usage error
//
// Prints GitHub Actions "::error file=...::" annotations, which show up on the
// run summary in Actions and read as plain lines anywhere else.

import { readFile } from 'node:fs/promises'
import validate from '@secvisogram/csaf-validator-lib/validate.js'
import * as basic from '@secvisogram/csaf-validator-lib/basic.js'

// basic = csaf_2_0_strict schema test + every mandatory test (6.1.x)
const tests = Object.values(basic)

const files = process.argv.slice(2)
if (files.length === 0) {
  console.error('usage: validate_csaf.mjs file.json [more.json ...]')
  process.exit(2)
}

let failed = 0
for (const file of files) {
  let doc
  try {
    doc = JSON.parse(await readFile(file, 'utf8'))
  } catch (e) {
    console.log(`::error file=${file}::cannot read JSON: ${e.message}`)
    failed++
    continue
  }

  const result = await validate(tests, doc)
  const bad = result.tests.filter((t) => !t.isValid)
  const warnings = result.tests.flatMap((t) =>
    t.warnings.map((w) => ({ test: t.name, ...w }))
  )

  if (result.isValid) {
    console.log(`OK    ${file}  (${result.tests.length} tests passed)`)
  } else {
    failed++
    console.log(`FAIL  ${file}`)
    for (const t of bad) {
      for (const err of t.errors) {
        console.log(
          `::error file=${file}::${t.name} ${err.instancePath || '/'}: ${err.message}`
        )
      }
    }
  }
  for (const w of warnings) {
    console.log(`::warning file=${file}::${w.test} ${w.instancePath || '/'}: ${w.message}`)
  }
}

console.log(`\n${files.length - failed}/${files.length} valid`)
process.exit(failed ? 1 : 0)

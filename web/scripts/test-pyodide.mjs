import assert from "node:assert/strict"
import { readFile } from "node:fs/promises"
import { dirname, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { loadPyodide } from "pyodide"

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const pythonPackage = resolve(projectRoot, "public", "py", "header_analyzer")
const sampleRoot = resolve(projectRoot, "tests", "samples")
const manifest = JSON.parse(await readFile(resolve(pythonPackage, "manifest.json"), "utf8"))
assert.ok(Array.isArray(manifest.files), "The generated Python manifest must contain a files array")

const pyodide = await loadPyodide()
pyodide.FS.mkdirTree("/home/pyodide/header_analyzer")
for (const file of manifest.files) {
  const contents = await readFile(resolve(pythonPackage, file), "utf8")
  pyodide.FS.writeFile(`/home/pyodide/header_analyzer/${file}`, contents)
}
pyodide.runPython(`
import sys, json
sys.path.insert(0, "/home/pyodide")
from header_analyzer import analyze
`)

const samples = [
  { file: "legit.eml", minimum: 0, maximum: 0 },
  { file: "phishing.eml", minimum: 45, maximum: 100 },
  { file: "legitimate_newsletter_links.eml", minimum: 0, maximum: 19 },
]

for (const sample of samples) {
  const raw = await readFile(resolve(sampleRoot, sample.file), "utf8")
  pyodide.globals.set("raw_email", raw)
  const serialized = pyodide.runPython(
    'json.dumps(analyze(raw_email.encode("utf-8")).to_dict(), ensure_ascii=False)',
  )
  assert.equal(typeof serialized, "string", `Python returned invalid output for ${sample.file}`)
  const report = JSON.parse(serialized)
  assert.ok(
    report.score >= sample.minimum && report.score <= sample.maximum,
    `${sample.file}: expected score ${sample.minimum}-${sample.maximum}, got ${report.score}`,
  )
  console.log(`${sample.file}: ${report.score}/100`)
}

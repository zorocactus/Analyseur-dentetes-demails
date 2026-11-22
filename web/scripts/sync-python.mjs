import { copyFile, mkdir, writeFile } from "node:fs/promises"
import { dirname, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const pythonSource = resolve(
  projectRoot,
  process.env.EMAIL_HEADER_ANALYZER_PATH ??
    "..\\python\\header_analyzer",
)
const pythonDestination = resolve(projectRoot, "public", "py", "header_analyzer")
const modules = ["__init__.py", "analyzer.py", "received.py", "links.py", "dns_checks.py"]

await mkdir(pythonDestination, { recursive: true })

for (const module of modules) {
  const source = resolve(pythonSource, module)
  await copyFile(source, resolve(pythonDestination, module))
}

const manifest = { files: modules }
await writeFile(
  resolve(pythonDestination, "manifest.json"),
  `${JSON.stringify(manifest, null, 2)}\n`,
  "utf8",
)

console.log(`Synced ${modules.length} Python modules from ${pythonSource}`)

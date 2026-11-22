import type { AnalysisReport, Finding } from "@/lib/types"

/**
 * Runs the source Python package in the browser. The email is never uploaded;
 * the optional DNS check sends only DNS query names to Cloudflare.
 */
const PYODIDE_VERSION = "0.26.4"
const BASE = `https://cdn.jsdelivr.net/pyodide/v${PYODIDE_VERSION}/full/`

type Pyodide = {
  FS: { mkdirTree(path: string): void; writeFile(path: string, data: string): void }
  globals: { set(name: string, value: unknown): void }
  runPython(code: string): unknown
}

type DnsAnswers = {
  records: Record<string, string[] | null>
  status: Record<string, string>
}

type PythonReport = {
  display_name: string
  sender: string
  reply_to: string
  return_path: string
  subject: string
  auth: { spf: string | null; dkim: string | null; dmarc: string | null }
  findings: Finding[]
  score: number
  hops: AnalysisReport["hops"]
  urls: AnalysisReport["urls"]
  dns: AnalysisReport["dns"]
}

declare global {
  interface Window {
    loadPyodide?: (options: { indexURL: string }) => Promise<Pyodide>
  }
}

let ready: Promise<Pyodide> | null = null

function loadScript(src: string): Promise<void> {
  return new Promise((resolve, reject) => {
    if (window.loadPyodide) return resolve()
    const script = document.createElement("script")
    script.src = src
    script.onload = () => resolve()
    script.onerror = () => reject(new Error("Impossible de charger Python dans le navigateur. Vérifie ta connexion internet (première utilisation) puis réessaie."))
    document.head.appendChild(script)
  })
}

function runPythonString(pyodide: Pyodide, code: string): string {
  const result = pyodide.runPython(code)
  if (typeof result !== "string") throw new Error("La réponse de Python est invalide.")
  return result
}

function getPyodide(): Promise<Pyodide> {
  ready ??= (async () => {
    await loadScript(`${BASE}pyodide.js`)
    if (!window.loadPyodide) throw new Error("Impossible d'initialiser Python dans le navigateur. Recharge la page puis réessaie.")
    const pyodide = await window.loadPyodide({ indexURL: BASE })
    pyodide.FS.mkdirTree("/home/pyodide/header_analyzer")

    const manifestResponse = await fetch("/py/header_analyzer/manifest.json")
    if (!manifestResponse.ok) throw new Error("Manifeste Python introuvable. Lance `pnpm sync:py` puis réessaie.")
    const manifest: unknown = await manifestResponse.json()
    if (
      typeof manifest !== "object" ||
      manifest === null ||
      !("files" in manifest) ||
      !Array.isArray(manifest.files) ||
      !manifest.files.every((file): file is string => typeof file === "string" && /^[a-zA-Z0-9_]+\.py$/.test(file))
    ) {
      throw new Error("Le manifeste des fichiers Python est invalide.")
    }

    for (const file of manifest.files) {
      const response = await fetch(`/py/header_analyzer/${file}`)
      if (!response.ok) throw new Error(`Fichier Python introuvable : public/py/header_analyzer/${file}`)
      pyodide.FS.writeFile(`/home/pyodide/header_analyzer/${file}`, await response.text())
    }
    pyodide.runPython(`
import sys, json
if "/home/pyodide" not in sys.path:
    sys.path.insert(0, "/home/pyodide")
from header_analyzer import analyze
from header_analyzer.dns_checks import needed_dns_queries
`)
    return pyodide
  })().catch((error) => { ready = null; throw error })
  return ready
}

/** Call at page load so the first scan can start faster. */
export function preloadPython(): Promise<void> {
  return getPyodide().then(() => undefined)
}

async function lookupTxt(name: string): Promise<{ records: string[] | null; status: string }> {
  const controller = new AbortController()
  const timeout = window.setTimeout(() => controller.abort(), 5000)
  try {
    const query = new URLSearchParams({ name, type: "TXT" })
    const response = await fetch(`https://cloudflare-dns.com/dns-query?${query}`, {
      headers: { accept: "application/dns-json" },
      signal: controller.signal,
      cache: "no-store",
    })
    if (!response.ok) return { records: null, status: "UNAVAILABLE" }

    const payload: unknown = await response.json()
    if (typeof payload !== "object" || payload === null || !("Status" in payload) || typeof payload.Status !== "number") {
      return { records: null, status: "UNAVAILABLE" }
    }
    if (payload.Status === 3) return { records: [], status: "NXDOMAIN" }
    if (payload.Status !== 0) return { records: null, status: "SERVFAIL" }

    const answers = "Answer" in payload && Array.isArray(payload.Answer) ? payload.Answer : []
    const records = answers.flatMap((answer): string[] => {
      if (typeof answer !== "object" || answer === null || !("type" in answer) || answer.type !== 16 || !("data" in answer) || typeof answer.data !== "string") {
        return []
      }
      return [answer.data]
    })
    return { records, status: "NOERROR" }
  } catch {
    return { records: null, status: "UNAVAILABLE" }
  } finally {
    window.clearTimeout(timeout)
  }
}

async function fetchDnsAnswers(pyodide: Pyodide, raw: string): Promise<DnsAnswers> {
  pyodide.globals.set("raw_email", raw)
  const serializedQueries = runPythonString(
    pyodide,
    "json.dumps(needed_dns_queries(raw_email.encode('utf-8')))",
  )
  const queries = JSON.parse(serializedQueries) as Array<[string, string]>
  const lookups = await Promise.all(queries.map(async ([name]) => [name, await lookupTxt(name)] as const))
  const records: DnsAnswers["records"] = {}
  const status: DnsAnswers["status"] = {}
  for (const [name, result] of lookups) {
    records[`TXT:${name}`] = result.records
    status[name] = result.status
  }
  return { records, status }
}

export async function analyzeEmail(raw: string, verifyDns = false): Promise<AnalysisReport> {
  if (!raw.trim()) throw new Error("Le fichier est vide. Choisis un email .eml qui contient des en-têtes.")

  const pyodide = await getPyodide()
  pyodide.globals.set("raw_email", raw)
  let dnsArguments = "None"
  if (verifyDns) {
    const answers = await fetchDnsAnswers(pyodide, raw)
    pyodide.globals.set("dns_records_json", JSON.stringify(answers.records))
    pyodide.globals.set("dns_status_json", JSON.stringify(answers.status))
    dnsArguments = "dns_records=json.loads(dns_records_json), dns_status=json.loads(dns_status_json)"
  }

  const serializedReport = runPythonString(
    pyodide,
    `json.dumps(analyze(raw_email.encode("utf-8"), ${dnsArguments}).to_dict(), ensure_ascii=False)`,
  )
  const data = JSON.parse(serializedReport) as PythonReport
  if (!data.sender) throw new Error("Ce fichier ne semble pas contenir un email valide. Vérifie qu’il s’agit bien d’un fichier .eml.")

  return {
    displayName: data.display_name,
    sender: data.sender,
    replyTo: data.reply_to,
    returnPath: data.return_path,
    subject: data.subject || "(sans sujet)",
    auth: { spf: data.auth.spf ?? null, dkim: data.auth.dkim ?? null, dmarc: data.auth.dmarc ?? null },
    findings: data.findings,
    score: data.score,
    hops: data.hops,
    urls: data.urls,
    dns: data.dns,
  }
}

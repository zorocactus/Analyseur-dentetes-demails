"use client"

import { useEffect, useRef, useState, type MouseEvent } from "react"
import { flushSync } from "react-dom"
import { AlertTriangle, Check, ChevronDown, Database, FileSearch, FileText, Globe, Link2, LoaderCircle, LockKeyhole, Mail, Moon, Route, ScanSearch, ShieldCheck, Sun, Upload, X, type LucideIcon } from "lucide-react"
import type { AnalysisReport, Finding, FindingCategory } from "@/lib/types"
import { analyzeEmail, preloadPython } from "@/lib/analyzer-pyodide"
import { Button } from "@/components/ui/button"

type Theme = "light" | "dark"
const DEMO = `Return-Path: <bounce@mailer-x9.ru>\nReceived: from unknown (HELO mailer-x9.ru) (185.220.101.5) by mx.example.org\nAuthentication-Results: mx.example.org; spf=fail smtp.mailfrom=mailer-x9.ru; dkim=none; dmarc=fail header.from=paypa1-secure.com\nFrom: "PayPal Support" <service@paypa1-secure.com>\nReply-To: help.desk.4421@gmail.com\nTo: victime@example.org\nSubject: Urgent: verify your account - compte suspendu\nMessage-ID: <20261120.8841@mailer-x9.ru>\nDate: Fri, 20 Nov 2026 08:12:00 +0000\n\nCliquez ici pour verifier votre compte.`
const TERMS = [
  ["SPF", "La liste des serveurs autorisés à envoyer des emails pour un domaine. « Validé » signifie que le serveur est autorisé ; « échec » est un indice suspect."],
  ["DKIM", "Une signature numérique invisible qui vérifie que le message vient bien du domaine annoncé et n’a pas été modifié."],
  ["DMARC", "Une règle qui combine SPF et DKIM : le domaine indiqué dans « De » doit correspondre au domaine vérifié. Un échec peut signaler une usurpation."],
  ["Validé, échec ou non fourni", "« Validé » : le contrôle a réussi. « Échec » : le contrôle a détecté un problème. « Non fourni » : aucun résultat n’est indiqué dans le fichier."],
  ["Reply-To", "L’adresse où votre réponse sera envoyée. Si elle diffère de l’expéditeur, surtout si c’est une adresse Gmail ou Yahoo, quelqu’un d’autre peut recevoir votre réponse."],
  ["Return-Path", "Une adresse technique utilisée pour les messages non distribués. Elle diffère souvent de l’expéditeur pour les newsletters légitimes."],
  ["Message-ID", "Un identifiant unique créé par le serveur d’envoi. Des services comme Amazon SES peuvent le créer ; une différence n’est pas forcément inquiétante."],
  ["Domaine ressemblant", "Un faux nom de domaine qui imite un vrai : « paypa1.com » remplace le l par un 1, « micosoft.com » manque une lettre, et « paypal.com.evil.ru » cache un autre domaine."],
  ["Score de risque", "Un score de 0 à 100. Plus le score est élevé, plus l’email présente de signes pouvant évoquer du phishing. Ce n’est pas une preuve."],
]

TERMS.push(
  ["Received", "Une ligne ajoutée par un serveur de messagerie à chaque étape du trajet de l’email. Les plus récentes se trouvent en haut."],
  ["Saut (hop)", "Une étape du parcours entre deux serveurs de messagerie. Les dates et adresses IP permettent de repérer des incohérences."],
  ["Enregistrement DNS", "Une information publiée pour un nom de domaine. SPF, DMARC et DKIM aident à vérifier quels serveurs peuvent envoyer des emails."],
  ["Politique DMARC", "La règle choisie par le domaine : p=none observe les résultats, p=quarantine demande de mettre les échecs en indésirables, p=reject demande de les refuser."],
  ["Sélecteur DKIM", "Le nom d’une clé de signature DKIM. Il permet de trouver la clé publique du domaine qui a signé le message."],
  ["Lien raccourci", "Une adresse courte qui redirige vers une autre page. Sa destination réelle est cachée tant qu’on ne l’ouvre pas."],
  ["URL « défangée »", "Une adresse rendue inoffensive à l’affichage, par exemple hxxps://exemple[.]com. Elle n’est pas cliquable et ne doit pas être ouverte."],
)

const CATEGORY_LABELS: Record<FindingCategory, string> = {
  auth: "Authentification",
  domain: "Domaine",
  headers: "En-têtes",
  routing: "Routage",
  links: "Liens",
  dns: "Vérification DNS",
}
const CATEGORY_ICONS: Record<FindingCategory, LucideIcon> = {
  auth: ShieldCheck,
  domain: Globe,
  headers: Mail,
  routing: Route,
  links: Link2,
  dns: Database,
}
const CATEGORY_ORDER: FindingCategory[] = ["auth", "domain", "headers", "routing", "links", "dns"]

function RiskGauge({ score }: { score: number }) {
  const [display, setDisplay] = useState(0)
  const [reduced, setReduced] = useState(false)
  useEffect(() => {
    const media = window.matchMedia("(prefers-reduced-motion: reduce)")
    setReduced(media.matches)
    if (media.matches) { setDisplay(score); return }
    let frame = 0
    const started = performance.now()
    const tick = (now: number) => {
      const progress = Math.min(1, (now - started) / 1500)
      setDisplay(Math.round(score * (1 - Math.pow(1 - progress, 4))))
      if (progress < 1) frame = requestAnimationFrame(tick)
    }
    frame = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(frame)
  }, [score])
  const hue = 120 - 1.2 * display
  const circumference = 2 * Math.PI * 76
  return <div className="relative grid size-48 shrink-0 place-items-center" role="img" aria-label={`Score de risque : ${score} sur 100`}>
    <svg viewBox="0 0 180 180" className="absolute inset-0 size-full -rotate-90" aria-hidden="true">
      <circle cx="90" cy="90" r="76" fill="none" stroke="currentColor" className="text-muted/50" strokeWidth="10" />
      <circle cx="90" cy="90" r="76" fill="none" stroke={`hsl(${hue} 68% 43%)`} strokeWidth="10" strokeLinecap="round" strokeDasharray={circumference} strokeDashoffset={circumference * (1 - display / 100)} style={{ transition: reduced ? "none" : "stroke-dashoffset 80ms linear" }} />
    </svg>
    <div className="text-center"><div className="text-6xl font-semibold tracking-[-0.06em] tabular-nums">{display}</div><div className="mt-1 text-sm text-muted-foreground">sur 100</div></div>
  </div>
}

function FindingCard({ finding }: { finding: Finding }) {
  const styles = { high: "border-l-red-500 bg-red-500/[0.045]", medium: "border-l-orange-500 bg-orange-500/[0.045]", low: "border-l-blue-500 bg-blue-500/[0.045]", info: "border-l-slate-400 bg-slate-500/[0.045]" }
  const labels = { high: "Grave", medium: "Moyen", low: "Mineur", info: "Info" }
  return <li className={`rounded-r-xl border-l-[3px] px-4 py-3 ${styles[finding.severity]}`}><div className="mb-1 flex items-center justify-between gap-3"><span className="text-sm font-semibold">{finding.message}</span><span className="shrink-0 rounded-full bg-background/80 px-2.5 py-1 text-xs font-medium text-muted-foreground">{labels[finding.severity]} · +{finding.points}</span></div></li>
}

function FindingsByCategory({ findings }: { findings: Finding[] }) {
  const groups = CATEGORY_ORDER
    .map((category) => ({ category, findings: findings.filter((finding) => finding.category === category) }))
    .filter((group) => group.findings.length > 0)
  return <div className="mt-7">
    <h3 className="mb-3 text-sm font-semibold">Résultats par catégorie</h3>
    {groups.length ? <div className="space-y-4">{groups.map(({ category, findings: grouped }) => {
      const Icon = CATEGORY_ICONS[category]
      return <section key={category} aria-label={CATEGORY_LABELS[category]}>
        <h4 className="mb-2 flex items-center gap-2 text-sm font-medium"><Icon className="size-4 text-indigo-600" aria-hidden="true" />{CATEGORY_LABELS[category]}</h4>
        <ul className="flex flex-col gap-2">{grouped.map((finding, index) => <FindingCard key={`${finding.code}-${index}`} finding={finding} />)}</ul>
      </section>
    })}</div> : <p className="rounded-xl bg-emerald-500/[0.06] px-4 py-3 text-sm text-emerald-800 dark:text-emerald-300">Aucune anomalie trouvée.</p>}
  </div>
}

function formatDelay(seconds: number): string {
  if (seconds < 60) return `${seconds} s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min`
  const hours = Math.floor(seconds / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  return minutes ? `${hours} h ${minutes} min` : `${hours} h`
}

function ReceivedTimeline({ hops }: { hops: AnalysisReport["hops"] }) {
  return <section className="mt-7" aria-labelledby="hops-title">
    <h3 id="hops-title" className="mb-3 flex items-center gap-2 text-sm font-semibold"><Route className="size-4 text-indigo-600" aria-hidden="true" />Parcours du mail</h3>
    {hops.length ? <ol className="ml-2 border-l border-indigo-500/30">
      {hops.map((hop, index) => <li key={`${hop.timestamp}-${index}`} className="relative pb-5 pl-5 last:pb-0">
        <span className="absolute -left-[5px] top-1 size-2.5 rounded-full bg-indigo-600 ring-4 ring-background" aria-hidden="true" />
        <p className="text-sm font-medium">{hop.from_name || "Serveur inconnu"} <span className="text-muted-foreground">→</span> {hop.by_name || "destination inconnue"}</p>
        <p className="mt-1 text-xs text-muted-foreground">{hop.timestamp ? new Date(hop.timestamp).toLocaleString("fr-FR") : "Date non indiquée"}</p>
        {hop.ips.length > 0 && <p className="mt-1 break-all text-xs text-muted-foreground">IP : {hop.ips.join(", ")}</p>}
        {hop.delay_seconds !== null && <p className="mt-1 text-xs text-muted-foreground">Délai depuis le saut précédent : {formatDelay(hop.delay_seconds)}</p>}
      </li>)}
    </ol> : <p className="rounded-xl bg-muted/60 px-4 py-3 text-sm text-muted-foreground">Aucun en-tête Received à afficher.</p>}
  </section>
}

function UrlResults({ urls }: { urls: AnalysisReport["urls"] }) {
  return <section className="mt-7" aria-labelledby="urls-title">
    <h3 id="urls-title" className="mb-3 flex items-center gap-2 text-sm font-semibold"><Link2 className="size-4 text-indigo-600" aria-hidden="true" />Liens trouvés</h3>
    {urls.length ? <ul className="space-y-2">{urls.map((url, index) => <li key={`${url.domain}-${index}`} className={`rounded-xl border p-4 ${url.flagged ? "border-orange-500/30 bg-orange-500/[0.04]" : "bg-muted/30"}`}>
      <p className="break-all font-mono text-xs" aria-label="Adresse neutralisée, non cliquable">{url.defanged}</p>
      {url.domain && <p className="mt-1 break-all text-xs text-muted-foreground">Domaine : {url.domain}</p>}
      {url.reasons.length > 0 && <ul className="mt-2 space-y-1 text-xs leading-5 text-muted-foreground">{url.reasons.map((reason, reasonIndex) => <li key={`${reasonIndex}-${reason}`}>{reason}</li>)}</ul>}
      {url.flagged && <span className="mt-2 inline-flex rounded-full bg-orange-500/10 px-2 py-1 text-xs font-medium text-orange-800 dark:text-orange-200">À examiner</span>}
    </li>)}</ul> : <p className="rounded-xl bg-muted/60 px-4 py-3 text-sm text-muted-foreground">Aucun lien trouvé dans le message.</p>}
  </section>
}

function DnsResults({ dns }: { dns: NonNullable<AnalysisReport["dns"]> }) {
  const recordLabel = (record: string | null | undefined, queryName: string) => {
    if (record) return record
    const query = dns.queries.find((item) => item.name === queryName)
    if (query && ["NOERROR", "NXDOMAIN"].includes(query.status)) return "Aucun enregistrement trouvé"
    return "Réponse indisponible"
  }
  const describeStatus = (status: string) => {
    if (status === "NOERROR") return "réponse reçue"
    if (status === "NXDOMAIN") return "nom de domaine inexistant"
    return "indisponible"
  }
  return <section className="mt-7 rounded-2xl border border-indigo-500/20 bg-indigo-500/[0.025] p-4 sm:p-5" aria-labelledby="dns-results-title">
    <h3 id="dns-results-title" className="mb-3 flex items-center gap-2 text-sm font-semibold"><Database className="size-4 text-indigo-600" aria-hidden="true" />Vérification DNS</h3>
    <p className="mb-4 text-xs leading-5 text-muted-foreground">{dns.available ? "Les réponses DNS ont été reçues." : "Certaines réponses DNS n’ont pas pu être obtenues."} Seuls des noms de domaine ont été envoyés à Cloudflare.</p>
    {dns.sender_domain && <p className="mb-3 break-all text-xs text-muted-foreground">Domaine expéditeur : {dns.sender_domain}</p>}
    <dl className="grid gap-2 text-xs sm:grid-cols-2">
      <div className="rounded-xl bg-background/70 p-3"><dt className="font-semibold">SPF</dt><dd className="mt-1 break-all text-muted-foreground">{recordLabel(dns.spf?.record, dns.sender_domain ?? "")}</dd></div>
      <div className="rounded-xl bg-background/70 p-3"><dt className="font-semibold">DMARC</dt><dd className="mt-1 break-all text-muted-foreground">{recordLabel(dns.dmarc?.record, dns.sender_domain ? `_dmarc.${dns.sender_domain}` : "")}</dd></div>
      {dns.dkim.map((key) => <div key={key.name} className="rounded-xl bg-background/70 p-3"><dt className="font-semibold">DKIM · {key.name}</dt><dd className="mt-1 break-all text-muted-foreground">{key.record ?? (key.available ? "Aucun enregistrement trouvé" : "Réponse indisponible")}</dd></div>)}
    </dl>
    {dns.queries.length > 0 && <ul className="mt-3 space-y-1 text-xs text-muted-foreground">{dns.queries.map((query) => <li key={`${query.name}-${query.type}`} className="break-all">{query.type} {query.name} — {describeStatus(query.status)}</li>)}</ul>}
  </section>
}

export function EmailAnalyzer() {
  const [file, setFile] = useState<File | null>(null)
  const [report, setReport] = useState<AnalysisReport | null>(null)
  const [error, setError] = useState("")
  const [dragging, setDragging] = useState(false)
  const [theme, setTheme] = useState<Theme | null>(null)
  const [isScanning, setIsScanning] = useState(false)
  const [verifyDns, setVerifyDns] = useState(false)
  const resultsRef = useRef<HTMLElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const resultTitle = report ? report.score >= 45 ? "Très probablement du phishing" : report.score >= 20 ? "Email suspect" : "Aucun signal fort détecté" : ""

  useEffect(() => {
    let active = true
    void preloadPython().catch((cause) => {
      if (active) setError(cause instanceof Error ? cause.message : "Impossible de charger Python dans le navigateur.")
    })
    return () => { active = false }
  }, [])

  useEffect(() => {
    const root = document.documentElement
    const initial: Theme = root.classList.contains("dark")
      ? "dark"
      : root.classList.contains("light")
        ? "light"
        : window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"
    root.classList.remove("dark", "light")
    root.classList.add(initial)
    setTheme(initial)
  }, [])
  function changeTheme(event: MouseEvent<HTMLButtonElement>) {
    if (!theme) return
    const next = theme === "dark" ? "light" : "dark"
    const bounds = event.currentTarget.getBoundingClientRect()
    const root = document.documentElement
    const applyTheme = () => flushSync(() => {
      root.classList.remove("dark", "light")
      root.classList.add(next)
      setTheme(next)
    })
    const transitionDocument = document as Document & {
      startViewTransition?: (callback: () => void) => unknown
    }
    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches

    if (reduceMotion || !transitionDocument.startViewTransition) {
      applyTheme()
      return
    }

    root.style.setProperty("--theme-x", `${bounds.left + bounds.width / 2}px`)
    root.style.setProperty("--theme-y", `${bounds.top + bounds.height / 2}px`)
    transitionDocument.startViewTransition(applyTheme)
  }
  function selectFile(selected: File | undefined) {
    if (!selected) return
    setError(""); setReport(null)
    if (!selected.name.toLowerCase().endsWith(".eml")) { setFile(null); setError("Choisis un fichier au format .eml pour lancer l’analyse."); return }
    setFile(selected)
  }
  async function scan() {
    if (!file || isScanning) return
    setError(""); setReport(null)
    setIsScanning(true)
    try {
      const raw = await file.text()
      const next = await analyzeEmail(raw, verifyDns)
      setReport(next)
      window.setTimeout(() => resultsRef.current?.scrollIntoView({ behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "instant" : "smooth", block: "start" }), 80)
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Une erreur est survenue pendant l’analyse.") }
    finally { setIsScanning(false) }
  }
  function loadExample() {
    setFile(new File([DEMO], "email-exemple-phishing.eml", { type: "message/rfc822" }))
    setReport(null); setError("")
  }
  const statuses = report ? ["spf", "dkim", "dmarc"].map((key) => ({ key: key.toUpperCase(), value: report.auth[key as keyof AnalysisReport["auth"]] })) : []

  return <main className="mx-auto min-h-screen w-full max-w-3xl px-5 pb-12 pt-6 sm:px-8 sm:pt-10">
    <header className="mb-9 flex items-center justify-between gap-4">
      <div><h1 className="text-lg font-semibold tracking-tight sm:text-xl">Analyseur d&apos;emails suspects</h1><p className="mt-0.5 hidden text-sm text-muted-foreground sm:block">Un premier regard pour repérer les signes de phishing</p></div>
      <Button variant="outline" size="icon" className="size-10 rounded-xl" onClick={changeTheme} disabled={theme === null} aria-label={theme === "dark" ? "Activer le thème clair" : "Activer le thème sombre"} title="Changer de thème">{theme === "dark" ? <Sun /> : <Moon />}</Button>
    </header>
    <p className="mb-6 text-sm leading-6 text-muted-foreground sm:hidden">Dépose un email au format .eml et découvre s&apos;il ressemble à du phishing.</p>

    <section className="rounded-3xl border bg-card p-5 shadow-sm sm:p-7" aria-labelledby="upload-title">
      <div className="mb-5"><h2 id="upload-title" className="text-base font-semibold">Vérifie un email</h2><p className="mt-1 text-sm text-muted-foreground">Dépose un fichier .eml pour repérer les signes suspects.</p></div>
      <input ref={inputRef} className="sr-only" type="file" accept=".eml,message/rfc822" aria-label="Choisir un fichier email au format .eml" onChange={(event) => selectFile(event.target.files?.[0])} />
      <div role="button" tabIndex={0} aria-label="Choisir ou déposer un fichier .eml" onClick={() => inputRef.current?.click()} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); inputRef.current?.click() } }} onDragOver={(event) => { event.preventDefault(); setDragging(true) }} onDragLeave={(event) => { if (!event.currentTarget.contains(event.relatedTarget as Node)) setDragging(false) }} onDrop={(event) => { event.preventDefault(); setDragging(false); selectFile(event.dataTransfer.files?.[0]) }} className={`group flex min-h-48 cursor-pointer flex-col items-center justify-center rounded-2xl border-2 border-dashed px-5 py-7 text-center outline-none transition-all focus-visible:ring-4 focus-visible:ring-indigo-500/20 ${dragging ? "scale-[1.01] border-indigo-500 bg-indigo-500/10" : "border-border hover:border-indigo-400 hover:bg-indigo-500/[0.03]"}`}>
        {file ? <><div className="mb-3 grid size-12 place-items-center rounded-2xl bg-indigo-500/10 text-indigo-600"><FileText aria-hidden="true" /></div><div className="flex max-w-full items-center gap-2"><span className="max-w-[min(65vw,360px)] truncate text-sm font-medium">{file.name}</span><button type="button" aria-label="Retirer le fichier" onClick={(event) => { event.stopPropagation(); setFile(null); setReport(null); if (inputRef.current) inputRef.current.value = "" }} className="grid size-8 shrink-0 place-items-center rounded-lg text-muted-foreground hover:bg-muted hover:text-foreground"><X className="size-4" /></button></div><span className="mt-1 text-xs text-muted-foreground">{(file.size / 1024).toFixed(1)} Ko · prêt à analyser</span></> : <><div className={`mb-4 grid size-12 place-items-center rounded-2xl transition-colors ${dragging ? "bg-indigo-600 text-white" : "bg-muted text-muted-foreground group-hover:bg-indigo-500/10 group-hover:text-indigo-600"}`}><Upload aria-hidden="true" /></div><p className="text-sm font-medium">Glisse ton fichier .eml ici ou clique pour le choisir</p><p className="mt-1.5 text-xs text-muted-foreground">Format .eml uniquement</p></>}
      </div>
      <div className="mt-4 flex flex-col gap-3 sm:flex-row">
        <Button className="h-11 flex-1 rounded-xl bg-indigo-600 font-medium text-white hover:bg-indigo-700" disabled={!file || isScanning} onClick={scan} aria-busy={isScanning}>
          {isScanning ? <LoaderCircle className="animate-spin" aria-hidden="true" /> : <ScanSearch aria-hidden="true" />}
          {isScanning ? "Analyse en cours…" : "Scanner"}
        </Button>
        <Button variant="outline" className="h-11 flex-1 rounded-xl" onClick={loadExample} disabled={isScanning}><FileSearch data-icon="inline-start" />Essayer avec un exemple</Button>
      </div>
      <div className="mt-4 rounded-xl border p-4">
        <label className="flex cursor-pointer items-center gap-3 text-sm font-medium">
          <input type="checkbox" role="switch" checked={verifyDns} onChange={(event) => setVerifyDns(event.target.checked)} aria-describedby="dns-privacy-note" className="size-4 accent-indigo-600" />
          Vérifier aussi le DNS
        </label>
        <p id="dns-privacy-note" className="mt-2 text-xs leading-5 text-muted-foreground">
          Les noms de domaine (pas le contenu du mail) seront envoyés à Cloudflare via DNS-over-HTTPS.
        </p>
      </div>
      {error && <p role="alert" className="mt-3 rounded-xl bg-red-500/10 px-4 py-3 text-sm font-medium text-red-700 dark:text-red-300">{error}</p>}
      <p className="mt-4 flex items-start gap-2 text-xs leading-5 text-muted-foreground"><LockKeyhole className="mt-0.5 size-4 shrink-0 text-emerald-600" aria-hidden="true" />Le contenu de ton email est analysé dans ton navigateur et n&apos;est jamais envoyé.</p>
    </section>

    <details className="group mt-4 rounded-2xl border bg-card px-5 py-4 shadow-sm">
      <summary className="flex cursor-pointer list-none items-center justify-between gap-3 text-sm font-medium [&::-webkit-details-marker]:hidden"><span>Je ne sais pas comment télécharger un email (.eml)</span><ChevronDown className="size-4 shrink-0 text-muted-foreground transition-transform group-open:rotate-180" /></summary>
      <div className="mt-4 grid gap-3 text-sm leading-6 text-muted-foreground sm:grid-cols-2"><div className="rounded-xl bg-muted/60 p-4"><strong className="text-foreground">Gmail</strong><p>Ouvre le mail → menu ⋮ en haut à droite → « Télécharger le message ».</p></div><div className="rounded-xl bg-muted/60 p-4"><strong className="text-foreground">Outlook</strong><p>Ouvre le mail → « Fichier » → « Enregistrer sous » → format .eml.</p></div><div className="rounded-xl bg-muted/60 p-4"><strong className="text-foreground">Thunderbird</strong><p>Clic droit sur le mail → « Enregistrer comme » → « Fichier .eml ».</p></div><div className="rounded-xl bg-muted/60 p-4"><strong className="text-foreground">Sur téléphone</strong><p>Le téléchargement est souvent plus simple depuis un ordinateur.</p></div></div>
      <p className="mt-4 flex items-center gap-2 rounded-xl border border-orange-500/20 bg-orange-500/5 p-3 text-sm font-medium text-orange-800 dark:text-orange-200"><AlertTriangle className="size-4 shrink-0" aria-hidden="true" />Ne clique sur aucun lien du mail suspect.</p>
    </details>

    {report && <section ref={resultsRef} className="mt-8 scroll-mt-6 animate-in fade-in slide-in-from-bottom-3 duration-500" aria-live="polite" aria-labelledby="results-title">
      <div className="mb-4 flex items-center gap-2"><ShieldCheck className="size-5 text-indigo-600" /><h2 id="results-title" className="text-lg font-semibold">Résultat de l’analyse</h2></div>
      <div className="rounded-3xl border bg-card p-5 shadow-sm sm:p-7"><div className="flex flex-col items-center gap-6 sm:flex-row sm:items-center sm:gap-8"><RiskGauge score={report.score} /><div className="min-w-0 flex-1 text-center sm:text-left"><p className={`text-xl font-semibold tracking-tight ${report.score >= 45 ? "text-red-600 dark:text-red-400" : report.score >= 20 ? "text-orange-600 dark:text-orange-400" : "text-emerald-700 dark:text-emerald-400"}`}>{resultTitle}</p><p className="mt-3 break-words text-sm leading-6 text-muted-foreground"><span className="font-medium text-foreground">De :</span> {report.displayName ? `${report.displayName} ` : ""}&lt;{report.sender}&gt;</p><p className="break-words text-sm leading-6 text-muted-foreground"><span className="font-medium text-foreground">Sujet :</span> {report.subject}</p></div></div>
        <div className="mt-7 grid gap-3 sm:grid-cols-3">{statuses.map(({ key, value }) => { const passed = value === "pass"; const failed = ["fail", "softfail", "permerror", "policy"].includes(value ?? ""); return <div key={key} className={`rounded-2xl border p-4 ${passed ? "border-emerald-600/20 bg-emerald-600/[0.05]" : failed ? "border-red-500/20 bg-red-500/[0.05]" : "border-orange-500/20 bg-orange-500/[0.05]"}`}><div className="flex items-center justify-between"><span className="text-sm font-semibold">{key}</span><span className={`flex items-center gap-1 text-xs font-medium ${passed ? "text-emerald-700 dark:text-emerald-400" : failed ? "text-red-700 dark:text-red-400" : "text-orange-800 dark:text-orange-300"}`}>{passed ? <><Check className="size-3.5" />Validé</> : failed ? <><X className="size-3.5" />Échec</> : "? Non fourni"}</span></div><p className="mt-2 truncate text-xs text-muted-foreground">Valeur trouvée : {value ?? "aucune"}</p></div> })}</div>
        <FindingsByCategory findings={report.findings} />
        <ReceivedTimeline hops={report.hops} />
        <UrlResults urls={report.urls} />
        {verifyDns && report.dns && <DnsResults dns={report.dns} />}
      </div>
    </section>}

    <section className="mt-8" aria-labelledby="glossary-title"><div className="mb-4 flex items-center gap-2"><Mail className="size-5 text-indigo-600" /><h2 id="glossary-title" className="text-lg font-semibold">Comprendre les termes</h2></div><div className="grid gap-3 sm:grid-cols-2">{TERMS.map(([term, explanation]) => <details key={term} className="group rounded-2xl border bg-card px-4 py-3.5 shadow-sm"><summary className="flex cursor-pointer list-none items-center justify-between gap-3 text-sm font-semibold [&::-webkit-details-marker]:hidden">{term}<ChevronDown className="size-4 shrink-0 text-muted-foreground transition-transform group-open:rotate-180" /></summary><p className="mt-2 text-sm leading-6 text-muted-foreground">{explanation}</p></details>)}</div></section>
    <footer className="mt-9 border-t pt-5 text-center text-xs leading-5 text-muted-foreground">Projet éducatif — les résultats sont des indices, pas des preuves.</footer>
  </main>
}

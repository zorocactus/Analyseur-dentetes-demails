export type Severity = "info" | "low" | "medium" | "high"

export type FindingCategory = "auth" | "domain" | "headers" | "routing" | "links" | "dns"

export type Finding = {
  code: string
  severity: Severity
  points: number
  message: string
  category: FindingCategory
}

export type ReceivedHop = {
  from_name: string
  by_name: string
  helo_name: string
  ips: string[]
  timestamp: string | null
  delay_seconds: number | null
}

export type FoundUrl = {
  defanged: string
  domain: string
  flagged: boolean
  reasons: string[]
}

export type DnsQuery = {
  name: string
  type: string
  status: string
}

export type DnsVerification = {
  available: boolean
  sender_domain?: string
  spf: { record: string | null; all_qualifier: string | null } | null
  dmarc: { record: string | null; policy: string | null } | null
  dkim: Array<{
    name: string
    record: string | null
    revoked: boolean
    available: boolean
  }>
  queries: DnsQuery[]
}

export type AnalysisReport = {
  displayName: string
  sender: string
  replyTo: string
  returnPath: string
  subject: string
  auth: { spf: string | null; dkim: string | null; dmarc: string | null }
  findings: Finding[]
  score: number
  hops: ReceivedHop[]
  urls: FoundUrl[]
  dns: DnsVerification | null
}

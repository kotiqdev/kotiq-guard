// Data-contract enums. Mirrors kotiq/models.py (string enums).

export enum Verdict {
  SAFE = 'SAFE',
  SUSPICIOUS = 'SUSPICIOUS',
  MALICIOUS = 'MALICIOUS',
  NEEDS_REVIEW = 'NEEDS_REVIEW',
}

// Per-finding severity. Ordered INFO < LOW < MEDIUM < HIGH < CRITICAL.
export enum Severity {
  INFO = 'INFO',
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL',
}

export enum Action {
  ALLOW = 'ALLOW',
  ALLOW_WITH_WARNING = 'ALLOW_WITH_WARNING',
  QUARANTINE = 'QUARANTINE',
  BLOCK = 'BLOCK',
}

export type Severity = "HIGH" | "MEDIUM" | "LOW" | "INFO";

export type Confidence = "HIGH" | "MEDIUM" | "LOW";

export type RiskLevel = "excellent" | "good" | "medium" | "high" | "critical";

export type FindingContext =
  | "app-code"
  | "api-code"
  | "test-code"
  | "example-code"
  | "docs-code"
  | "github-actions"
  | "release-tooling"
  | "cli-tooling"
  | "generated-code"
  | "template-code"
  | "unknown";

export type ProjectInfo = {
  name?: string;
  framework: "nextjs" | "react" | "node" | "unknown";
  router?: "app" | "pages" | "mixed" | "unknown";
  language: "typescript" | "javascript" | "mixed" | "unknown";
};

export type Finding = {
  id: string;
  ruleId: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  originalSeverity?: Severity;
  originalConfidence?: Confidence;
  contextAdjustmentReason?: string;
  category: string;
  filePath: string;
  context?: FindingContext;
  contextReason?: string;
  line?: number;
  column?: number;
  evidence?: string;
  evidencePath?: string;
  description: string;
  recommendation: string;
  references?: string[];
};

export type ScanSummary = {
  score: number;
  riskLevel: RiskLevel;
  totalFindings: number;
  high: number;
  medium: number;
  low: number;
  info: number;
};

export type ScanResult = {
  project: ProjectInfo;
  summary: ScanSummary;
  findings: Finding[];
  metadata: {
    scannedAt: string;
    durationMs: number;
    toolVersion: string;
  };
};

export type SourceFile = {
  path: string;
  absolutePath: string;
  content: string;
  lines: string[];
};

export type ScanContext = {
  targetPath: string;
  rootPath: string;
  files: SourceFile[];
  project: ProjectInfo;
  middleware?: MiddlewareSignal[];
  packageJson?: {
    name?: string;
    dependencies: Record<string, string>;
    devDependencies: Record<string, string>;
  };
};

export type MiddlewareSignal = {
  filePath: string;
  hasAuthSignal: boolean;
  hasRateLimitSignal: boolean;
  matchers: string[];
  scopeRoot?: string;
};

export type Rule = {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  confidence?: Confidence;
  scan(context: ScanContext): Promise<Finding[]> | Finding[];
};

export type ScanOptions = {
  categories?: string[];
  contextTuning?: "standard" | "off";
  excludePaths?: string[];
  rules?: Rule[];
  toolVersion?: string;
};

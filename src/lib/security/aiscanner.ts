// src/lib/security/aiscanner.ts

import { ThreatCategory, ThreatSeverity, ThreatMatch } from '@/types/security';
import { ruleEngine } from './rules';
import { PayloadNormalizer } from './normalizer';
import { EntropyScorer } from './entropy-scorer';
import { EmbeddingGuard } from './embedding-guard';
import { DatasetLoader } from './dataset-loader';

export interface AIScanResult {
  safe: boolean;
  threats: ThreatMatch[];
  confidence: number;
  category?: string;
  reason?: string;
  layers: {
    signature: boolean;
    entropy: boolean;
    embedding: boolean;
  };
  metadata?: {
    entropyScore?: number;
    embeddingSimilarity?: number;
    normalizedText?: string;
  };
}

const SEVERITY_SCORE: Record<string, number> = {
  CRITICAL: 0.95,
  HIGH: 0.75,
  MEDIUM: 0.50,
  LOW: 0.25,
};

export class AIScanner {
  private normalizer: PayloadNormalizer;
  private entropyScorer: EntropyScorer;
  private embeddingGuard: EmbeddingGuard;
  private datasetLoader: DatasetLoader;

  constructor() {
    this.normalizer = new PayloadNormalizer();
    this.entropyScorer = new EntropyScorer();
    this.embeddingGuard = new EmbeddingGuard();
    this.datasetLoader = new DatasetLoader();
  }

  /**
   * 🔍 MAIN SCAN METHOD — All 3 Layers
   */
  scan(input: string): AIScanResult {
    if (!input || typeof input !== 'string') {
      return this.buildResult([], 0, undefined, undefined, false, false, false, {});
    }

    const threats: ThreatMatch[] = [];

    // ═══════════════════════════════════════════════════════════════
    // LAYER 1: Preprocessing & Signature Detection
    // ═══════════════════════════════════════════════════════════════
    const normalized = this.normalizer.normalize(input);

    const signatureThreats = ruleEngine.scan(input) || [];
    const normalizedThreats = ruleEngine.scan(normalized) || [];

    threats.push(...signatureThreats, ...normalizedThreats);

    const hasSignatureThreat = signatureThreats.length > 0 || normalizedThreats.length > 0;

    // ═══════════════════════════════════════════════════════════════
    // LAYER 2: Entropy & Perplexity Analysis
    // ═══════════════════════════════════════════════════════════════
    const entropyResult = this.entropyScorer.analyze(input);

    if (entropyResult.isAnomaly) {
      threats.push({
        id: 'ENTROPY-001',
        category: ThreatCategory.ENCODING_EVASION,
        severity: entropyResult.score > 0.8 ? ThreatSeverity.CRITICAL : ThreatSeverity.HIGH,
        pattern: 'entropy_analysis',
        matchedPayload: input.substring(0, 50),
        description: entropyResult.details,
        timestamp: Date.now(),
        layer: 'ENTROPY',
      });
    }

    // ═══════════════════════════════════════════════════════════════
    // LAYER 3: System Prompt Leakage Detection
    // ═══════════════════════════════════════════════════════════════
    const embeddingResult = this.embeddingGuard.checkLeakage(input);

    if (embeddingResult.isLeak) {
      threats.push({
        id: 'EMBED-001',
        category: ThreatCategory.SYSTEM_EXTRACTION,
        severity: embeddingResult.similarity > 0.85 ? ThreatSeverity.CRITICAL : ThreatSeverity.HIGH,
        pattern: 'embedding_similarity',
        matchedPayload: embeddingResult.matchedPhrases.join(', ').substring(0, 100),
        description: embeddingResult.details,
        timestamp: Date.now(),
        layer: 'EMBEDDING',
      });
    }

    // ═══════════════════════════════════════════════════════════════
    // CONFIDENCE SCORING (reporting only — does NOT decide safe/unsafe)
    // ═══════════════════════════════════════════════════════════════
    let maxConfidence = 0;
    let primaryCategory: string | undefined;
    let primaryReason: string | undefined;

    for (const threat of threats) {
      const key = String(threat.severity).toUpperCase();
      const score = SEVERITY_SCORE[key] ?? 0.5;
      if (score > maxConfidence) {
        maxConfidence = score;
        primaryCategory = threat.category;
        primaryReason = threat.description;
      }
    }

    // ═══════════════════════════════════════════════════════════════
    // FINAL DECISION — ANY real detection = unsafe. Period.
    // ═══════════════════════════════════════════════════════════════
    const isSafe = threats.length === 0
      && !hasSignatureThreat
      && !entropyResult.isAnomaly
      && !embeddingResult.isLeak;

    return this.buildResult(
      threats,
      maxConfidence,
      isSafe ? undefined : primaryCategory,
      isSafe ? undefined : primaryReason,
      hasSignatureThreat,
      entropyResult.isAnomaly,
      embeddingResult.isLeak,
      {
        entropyScore: entropyResult.score,
        embeddingSimilarity: embeddingResult.similarity,
        normalizedText: normalized.substring(0, 200),
      },
      isSafe
    );
  }

  private buildResult(
    threats: ThreatMatch[],
    confidence: number,
    category: string | undefined,
    reason: string | undefined,
    signature: boolean,
    entropy: boolean,
    embedding: boolean,
    metadata: AIScanResult['metadata'],
    safeOverride?: boolean
  ): AIScanResult {
    const safe = safeOverride !== undefined
      ? safeOverride
      : threats.length === 0 && !signature && !entropy && !embedding;

    return {
      safe,
      threats,
      confidence: parseFloat(confidence.toFixed(4)),
      category,
      reason,
      layers: { signature, entropy, embedding },
      metadata,
    };
  }

  /**
   * 🧪 Run Red-Teaming Test Suite
   */
  async runRedTeamTests(): Promise<string> {
    const result = await this.datasetLoader.runTests((input) => this.scan(input));
    return this.datasetLoader.generateReport(result);
  }

  /**
   * 📊 Get Dataset Loader for custom tests
   */
  getDatasetLoader(): DatasetLoader {
    return this.datasetLoader;
  }

  /**
   * 🔐 Configure System Prompt for Leakage Detection
   */
  setSystemPrompt(prompt: string): void {
    this.embeddingGuard.setSystemPrompt(prompt);
  }
}

// Singleton export
export const aiScanner = new AIScanner();
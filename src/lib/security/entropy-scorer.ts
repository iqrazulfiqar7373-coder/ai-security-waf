// src/lib/security/entropy-scorer.ts

/**
 * 🧠 Entropy & Perplexity Scorer
 * Detects obfuscated/encoded jailbreak prompts using statistical analysis
 */

export interface EntropyResult {
  score: number;        // 0.0 to 1.0
  entropy: number;      // Shannon entropy
  perplexity: number;   // Approximate perplexity
  isAnomaly: boolean;   // True if suspicious
  details: string;
}

export class EntropyScorer {
  // Thresholds tuned for jailbreak detection
  private readonly HIGH_ENTROPY_THRESHOLD = 4.8;
  private readonly LOW_ENTROPY_THRESHOLD = 2.5;
  private readonly PERPLEXITY_THRESHOLD = 3.5;
  
  // Common English character frequencies (for comparison)
  private readonly ENGLISH_FREQ: Record<string, number> = {
    'e': 0.127, 't': 0.091, 'a': 0.082, 'o': 0.075, 'i': 0.070,
    'n': 0.067, 's': 0.063, 'h': 0.061, 'r': 0.060, 'd': 0.043,
    'l': 0.040, 'c': 0.028, 'u': 0.028, 'm': 0.024, 'w': 0.024,
    'f': 0.022, 'g': 0.020, 'y': 0.020, 'p': 0.019, 'b': 0.015,
    'v': 0.010, 'k': 0.008, 'j': 0.002, 'x': 0.002, 'q': 0.001,
    'z': 0.001
  };

  analyze(text: string): EntropyResult {
    if (!text || text.length < 10) {
      return { score: 0, entropy: 0, perplexity: 0, isAnomaly: false, details: 'Text too short' };
    }

    const cleanText = text.toLowerCase().replace(/[^a-z0-9\s]/g, '');
    
    // 1. Shannon Entropy Calculation
    const entropy = this.calculateShannonEntropy(cleanText);
    
    // 2. Character Distribution Analysis
    const distribution = this.calculateDistribution(cleanText);
    const chiSquare = this.chiSquareTest(distribution);
    
    // 3. Repetition Pattern Detection
    const repetitionScore = this.detectRepetition(text);
    
    // 4. N-gram Analysis (bigram/trigram randomness)
    const ngramScore = this.ngramAnalysis(cleanText);
    
    // 5. Special Character Density
    const specialCharRatio = this.specialCharDensity(text);
    
    // 6. Approximate Perplexity
    const perplexity = this.estimatePerplexity(entropy, chiSquare, ngramScore);

    // Composite Scoring
    let anomalyScore = 0;
    let reasons: string[] = [];

    // High entropy = possible encoding/obfuscation
    if (entropy > this.HIGH_ENTROPY_THRESHOLD) {
      anomalyScore += 0.35;
      reasons.push(`High entropy (${entropy.toFixed(2)})`);
    }
    
    // Low entropy = possible padding/repetition attacks
    if (entropy < this.LOW_ENTROPY_THRESHOLD && text.length > 50) {
      anomalyScore += 0.25;
      reasons.push(`Suspiciously low entropy (${entropy.toFixed(2)})`);
    }

    // Chi-square deviation from English
    if (chiSquare > 500) {
      anomalyScore += 0.25;
      reasons.push(`Abnormal character distribution (χ²=${chiSquare.toFixed(0)})`);
    }

    // Repetition patterns
    if (repetitionScore > 0.3) {
      anomalyScore += 0.20;
      reasons.push(`Repetition patterns detected (${(repetitionScore * 100).toFixed(0)}%)`);
    }

    // N-gram anomaly
    if (ngramScore > 0.7) {
      anomalyScore += 0.25;
      reasons.push(`Abnormal n-gram structure`);
    }

    // High special character density
    if (specialCharRatio > 0.25) {
      anomalyScore += 0.20;
      reasons.push(`High special character density (${(specialCharRatio * 100).toFixed(0)}%)`);
    }

    // Perplexity check
    if (perplexity > this.PERPLEXITY_THRESHOLD) {
      anomalyScore += 0.30;
      reasons.push(`High perplexity (${perplexity.toFixed(2)})`);
    }

    const finalScore = Math.min(anomalyScore, 1.0);
    
    return {
      score: parseFloat(finalScore.toFixed(4)),
      entropy: parseFloat(entropy.toFixed(4)),
      perplexity: parseFloat(perplexity.toFixed(4)),
      isAnomaly: finalScore > 0.55,
      details: reasons.length > 0 ? reasons.join('; ') : 'Normal distribution'
    };
  }

  private calculateShannonEntropy(text: string): number {
    const freq: Record<string, number> = {};
    const len = text.length;
    
    for (const char of text) {
      freq[char] = (freq[char] || 0) + 1;
    }
    
    let entropy = 0;
    for (const char in freq) {
      const p = freq[char] / len;
      entropy -= p * Math.log2(p);
    }
    
    return entropy;
  }

  private calculateDistribution(text: string): Record<string, number> {
    const freq: Record<string, number> = {};
    const len = text.length;
    
    for (const char of text) {
      if (/[a-z]/.test(char)) {
        freq[char] = (freq[char] || 0) + 1;
      }
    }
    
    const dist: Record<string, number> = {};
    for (const char in freq) {
      dist[char] = freq[char] / len;
    }
    
    return dist;
  }

  private chiSquareTest(observed: Record<string, number>): number {
    let chiSquare = 0;
    const totalChars = Object.values(observed).reduce((a, b) => a + b, 0);
    
    if (totalChars === 0) return 0;
    
    for (const char in this.ENGLISH_FREQ) {
      const expected = this.ENGLISH_FREQ[char] * totalChars;
      const obs = (observed[char] || 0) * totalChars;
      
      if (expected > 0) {
        chiSquare += Math.pow(obs - expected, 2) / expected;
      }
    }
    
    return chiSquare;
  }

  private detectRepetition(text: string): number {
    // Detect repeated substrings (common in padding attacks)
    const len = text.length;
    if (len < 20) return 0;
    
    let repeatedChars = 0;
    
    // Check for repeated characters (e.g., "aaaaa", "!!!!!")
    for (let i = 0; i < len - 2; i++) {
      if (text[i] === text[i + 1] && text[i] === text[i + 2]) {
        repeatedChars++;
      }
    }
    
    // Check for repeated patterns (e.g., "abcabcabc")
    let patternMatches = 0;
    for (let patternLen = 3; patternLen <= Math.min(20, len / 2); patternLen++) {
      const pattern = text.substring(0, patternLen);
      let count = 0;
      for (let i = 0; i <= len - patternLen; i += patternLen) {
        if (text.substring(i, i + patternLen) === pattern) count++;
      }
      if (count > 2) patternMatches += count;
    }
    
    return Math.min((repeatedChars + patternMatches * 2) / len, 1.0);
  }

  private ngramAnalysis(text: string): number {
    // Bigram analysis - normal English has predictable bigrams
    const bigrams: Record<string, number> = {};
    const total = text.length - 1;
    
    if (total < 1) return 0;
    
    for (let i = 0; i < total; i++) {
      const bigram = text.substring(i, i + 2);
      bigrams[bigram] = (bigrams[bigram] || 0) + 1;
    }
    
    // Calculate bigram entropy (high = random/gibberish)
    let entropy = 0;
    for (const bg in bigrams) {
      const p = bigrams[bg] / total;
      entropy -= p * Math.log2(p);
    }
    
    // Normalize: English text ~3-4, random ~6-8
    return Math.max(0, (entropy - 3) / 5);
  }

  private specialCharDensity(text: string): number {
    const special = text.replace(/[a-zA-Z0-9\s]/g, '').length;
    return special / text.length;
  }

  private estimatePerplexity(entropy: number, chiSquare: number, ngramScore: number): number {
    // Approximate perplexity based on multiple signals
    const basePpl = Math.pow(2, entropy);
    const chiFactor = Math.log10(chiSquare + 1) / 3;
    return (basePpl * 0.5 + chiFactor * 2 + ngramScore * 5) / 3;
  }
}
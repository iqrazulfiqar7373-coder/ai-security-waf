// src/lib/security/embedding-guard.ts

/**
 * 🔐 System Prompt Leakage Detector
 * Uses local vector similarity to detect if output resembles system prompt
 * 
 * NOTE: For production, replace with OpenAI/embedding API
 * This is a lightweight local implementation
 */

export interface SimilarityResult {
  similarity: number;   // 0.0 to 1.0
  isLeak: boolean;      // True if system prompt leaking
  matchedPhrases: string[];
  details: string;
}

export class EmbeddingGuard {
  // Your system prompt keywords/phrases (customize these!)
  private systemPromptSignatures: string[] = [
    'you are an ai assistant',
    'you are a helpful assistant',
    'you are an advanced language model',
    'you are a large language model',
    'as an ai language model',
    'as an ai assistant',
    'my training data',
    'my knowledge cutoff',
    'i cannot provide',
    'i cannot assist',
    'i cannot help',
    'i apologize, but',
    'i am not able to',
    'i must decline',
    'i cannot fulfill',
    'i cannot comply',
    'harmful content',
    'illegal activities',
    'ethical guidelines',
    'safety guidelines',
    'content policy',
    'usage policy',
    'system instruction',
    'developer instruction',
    'model behavior',
    'ai alignment',
    'constitutional ai',
    'rlhf',
    'reinforcement learning',
    'training process',
    'fine-tuned',
    'base model',
    'inference',
    'token limit',
    'context window',
    'temperature',
    'top_p',
    'frequency penalty',
    'presence penalty',
  ];

  // High-value keywords that strongly indicate leakage
  private highValueKeywords: string[] = [
    'system prompt',
    'system instruction',
    'developer message',
    'base prompt',
    'initial prompt',
    'hidden instruction',
    'preprompt',
    'meta prompt',
    'system role',
    'you are gpt',
    'you are claude',
    'you are kimi',
    'you are llama',
    'you are gemini',
    'you are bard',
    'openai',
    'anthropic',
    'moonshot ai',
    'model card',
    'system card',
  ];

  checkLeakage(text: string): SimilarityResult {
    if (!text || text.length < 20) {
      return { similarity: 0, isLeak: false, matchedPhrases: [], details: 'Text too short' };
    }

    const normalizedText = text.toLowerCase();
    const words = this.tokenize(normalizedText);
    
    let totalScore = 0;
    const matchedPhrases: string[] = [];
    
    // 1. Check for exact signature phrases
    for (const signature of this.systemPromptSignatures) {
      if (normalizedText.includes(signature)) {
        totalScore += 0.15;
        matchedPhrases.push(signature);
      }
    }

    // 2. Check for high-value keywords (stronger signal)
    for (const keyword of this.highValueKeywords) {
      if (normalizedText.includes(keyword)) {
        totalScore += 0.25;
        matchedPhrases.push(`[HIGH] ${keyword}`);
      }
    }

    // 3. TF-IDF-like similarity scoring
    const tfidfScore = this.tfidfSimilarity(words);
    totalScore += tfidfScore * 0.4;

    // 4. Check for "You are..." pattern repetition (common in system prompts)
    const youArePattern = (normalizedText.match(/you\s+are\s+(?:an?\s+)?/g) || []).length;
    if (youArePattern > 2) {
      totalScore += 0.15;
      matchedPhrases.push(`"You are" repetition (${youArePattern}x)`);
    }

    // 5. Check for instruction list patterns
    const instructionPatterns = [
      /do\s+not\s+\w+/g,
      /never\s+\w+/g,
      /always\s+\w+/g,
      /must\s+not\s+\w+/g,
      /should\s+not\s+\w+/g,
      /cannot\s+\w+/g,
      /refuse\s+to\s+\w+/g,
    ];
    
    let instructionCount = 0;
    for (const pattern of instructionPatterns) {
      const matches = normalizedText.match(pattern);
      if (matches) instructionCount += matches.length;
    }
    
    if (instructionCount > 3) {
      totalScore += 0.20;
      matchedPhrases.push(`Instruction patterns (${instructionCount})`);
    }

    // 6. N-gram overlap with common system prompt structures
    const ngramOverlap = this.ngramOverlap(normalizedText);
    totalScore += ngramOverlap * 0.3;

    const finalSimilarity = Math.min(totalScore, 1.0);
    
    return {
      similarity: parseFloat(finalSimilarity.toFixed(4)),
      isLeak: finalSimilarity > 0.70,
      matchedPhrases: [...new Set(matchedPhrases)],
      details: this.generateDetails(finalSimilarity, matchedPhrases)
    };
  }

  private tokenize(text: string): string[] {
    return text
      .replace(/[^\w\s]/g, ' ')
      .split(/\s+/)
      .filter(w => w.length > 2);
  }

  private tfidfSimilarity(words: string[]): number {
    // Simple TF-based scoring
    const tf: Record<string, number> = {};
    const totalWords = words.length;
    
    for (const word of words) {
      tf[word] = (tf[word] || 0) + 1;
    }
    
    // Check overlap with system prompt vocabulary
    const systemVocab = new Set([
      ...this.systemPromptSignatures.flatMap(s => s.split(' ')),
      ...this.highValueKeywords.flatMap(s => s.split(' ')),
    ]);
    
    let overlapScore = 0;
    for (const word in tf) {
      if (systemVocab.has(word)) {
        overlapScore += tf[word] / totalWords;
      }
    }
    
    return Math.min(overlapScore * 5, 1.0);
  }

  private ngramOverlap(text: string): number {
    // Check for common system prompt n-grams
    const commonNgrams = [
      'you are an ai',
      'you are a helpful',
      'as an ai',
      'i cannot provide',
      'i cannot assist',
      'i apologize but',
      'harmful or illegal',
      'not able to',
      'against my',
      'my guidelines',
      'safety guidelines',
      'ethical guidelines',
      'content policy',
      'training data',
      'knowledge cutoff',
    ];
    
    let matches = 0;
    for (const ngram of commonNgrams) {
      if (text.includes(ngram)) matches++;
    }
    
    return Math.min(matches / 5, 1.0);
  }

  private generateDetails(similarity: number, phrases: string[]): string {
    if (similarity > 0.85) {
      return `CRITICAL: High similarity (${(similarity * 100).toFixed(1)}%) to system prompt. ${phrases.length} indicators matched.`;
    } else if (similarity > 0.70) {
      return `HIGH: Moderate similarity (${(similarity * 100).toFixed(1)}%) to system prompt. Possible leakage.`;
    } else if (similarity > 0.40) {
      return `MEDIUM: Some system-like phrases detected (${(similarity * 100).toFixed(1)}%).`;
    }
    return `LOW: No significant system prompt leakage detected (${(similarity * 100).toFixed(1)}%).`;
  }

  // Optional: Add your own system prompt for comparison
  setSystemPrompt(prompt: string): void {
    // Extract key phrases from custom system prompt
    const phrases = prompt
      .toLowerCase()
      .split(/[.!?]/)
      .map(s => s.trim())
      .filter(s => s.length > 10);
    
    this.systemPromptSignatures = [...new Set([...this.systemPromptSignatures, ...phrases])];
  }
}
// src/lib/security/rules.ts

import { ThreatCategory, ThreatSeverity, ThreatMatch } from '@/types/security';

interface SecurityRule {
  id: string;
  category: ThreatCategory;
  severity: ThreatSeverity;
  patterns: RegExp[];
  description: string;
}

class SecurityRuleEngine {
  private static instance: SecurityRuleEngine;
  private rules: SecurityRule[] = [];

  private constructor() {
    this.initializeRules();
  }

  static getInstance(): SecurityRuleEngine {
    if (!SecurityRuleEngine.instance) {
      SecurityRuleEngine.instance = new SecurityRuleEngine();
    }
    return SecurityRuleEngine.instance;
  }

  private initializeRules(): void {
    this.rules = [
      // SQL Injection
      {
        id: 'SQLI-001',
        category: ThreatCategory.SQL_INJECTION,
        severity: ThreatSeverity.CRITICAL,
        patterns: [
          /(\bUNION\s+(?:ALL\s+)?SELECT\b)/i,
          /(\bSELECT\b.*\bFROM\b)/i,
          /('\s*OR\s+'1'?\s*=\s*'1)/i,
          /(';\s*DROP\s+TABLE\b)/i,
          /(\bINSERT\s+INTO\b.*\bVALUES\b)/i,
          /(\bDELETE\s+FROM\b)/i,
          /(\bUPDATE\b.*\bSET\b)/i,
          /(\bEXEC\b.*\bxp_cmdshell\b)/i,
          /(\bWAITFOR\s+DELAY\b)/i,
          /(;\s*--)/i,
        ],
        description: 'SQL Injection attempt detected',
      },
      {
        id: 'SQLI-002',
        category: ThreatCategory.SQL_INJECTION,
        severity: ThreatSeverity.CRITICAL,
        patterns: [
          /(\bSLEEP\s*\(.*\))/i,
          /(\bBENCHMARK\s*\(.*\))/i,
          /(\bINFORMATION_SCHEMA\b)/i,
          /(\bGROUP_CONCAT\b)/i,
          /(\bLOAD_FILE\b)/i,
          /(\bINTO\s+OUTFILE\b)/i,
        ],
        description: 'Advanced SQL Injection detected',
      },
      // NoSQL Injection
      {
        id: 'NOSQLI-001',
        category: ThreatCategory.NOSQL_INJECTION,
        severity: ThreatSeverity.CRITICAL,
        patterns: [
          /(\{\s*"\$ne"\s*:\s*)/i,
          /(\{\s*"\$eq"\s*:\s*)/i,
          /(\{\s*"\$gt"\s*:\s*)/i,
          /(\{\s*"\$lt"\s*:\s*)/i,
          /(\{\s*"\$regex"\s*:\s*)/i,
          /(\{\s*"\$where"\s*:\s*)/i,
          /(\{\s*"\$exists"\s*:\s*true\})/i,
          /(\bdocument\.cookie\b)/i,
        ],
        description: 'NoSQL Injection attempt detected',
      },
      // XSS
      {
        id: 'XSS-001',
        category: ThreatCategory.XSS,
        severity: ThreatSeverity.HIGH,
        patterns: [
          /(<script\b[^>]*>)/i,
          /(<script[\s\S]*?<\/script>)/i,
          /(javascript\s*:)/i,
          /(on\w+\s*=\s*["']?)/i,
          /(<\s*iframe\b[^>]*>)/i,
          /(<\s*embed\b[^>]*>)/i,
          /(<\s*object\b[^>]*>)/i,
          /(<\s*svg\b[^>]*on\w+)/i,
          /(document\.cookie)/i,
          /(window\.location)/i,
          /(eval\s*\(.*\))/i,
          /(document\.write\s*\()/i,
        ],
        description: 'Cross-Site Scripting (XSS) attempt detected',
      },
      {
        id: 'XSS-002',
        category: ThreatCategory.XSS,
        severity: ThreatSeverity.HIGH,
        patterns: [
          /(<img[^>]+onerror\s*=)/i,
          /(<body[^>]+onload\s*=)/i,
          /(<input[^>]+onfocus\s*=)/i,
          /(expression\s*\(.*\))/i,
          /(<link[^>]+)/i,
          /(<meta[^>]+)/i,
          /(<video[^>]+on\w+)/i,
          /(<audio[^>]+on\w+)/i,
        ],
        description: 'Advanced XSS attempt detected',
      },
      // Command Injection
      {
        id: 'CMDI-001',
        category: ThreatCategory.COMMAND_INJECTION,
        severity: ThreatSeverity.CRITICAL,
        patterns: [
          /(;\s*(?:ls|cat|pwd|id|whoami|uname))/i,
          /(&&\s*(?:ls|cat|pwd|id|whoami|uname))/i,
          /(\|\|\s*(?:ls|cat|pwd|id|whoami|uname))/i,
          /(\|\s*(?:ls|cat|pwd|id|whoami|uname))/i,
          /(`[^`]*`)/,
          /(\$\([^)]*\))/,
          /(system\s*\(.*\))/i,
          /(exec\s*\(.*\))/i,
          /(passthru\s*\(.*\))/i,
          /(shell_exec\s*\(.*\))/i,
        ],
        description: 'Command Injection attempt detected',
      },
      {
        id: 'CMDI-002',
        category: ThreatCategory.COMMAND_INJECTION,
        severity: ThreatSeverity.CRITICAL,
        patterns: [
          /(rm\s+-rf\b)/i,
          /(\/etc\/passwd)/i,
          /(\/etc\/shadow)/i,
          /(c:\/windows\/system32)/i,
          /(wget\s+http)/i,
          /(curl\s+http)/i,
          /(nc\s+-[lne])/i,
          /(\/bin\/bash)/i,
          /(\/bin\/sh)/i,
          /(cmd\.exe)/i,
        ],
        description: 'Dangerous system command detected',
      },
      // Path Traversal
      {
        id: 'PT-001',
        category: ThreatCategory.PATH_TRAVERSAL,
        severity: ThreatSeverity.HIGH,
        patterns: [
          /(\.\.\/)/,
          /(\.\.\\)/,
          /(%2e%2e%2f)/i,
          /(%2e%2e\/)/i,
          /(\.\.%2f)/i,
          /(%2e%2e%5c)/i,
          /(\.\.%5c)/i,
          /(\/etc\/passwd)/i,
          /(\\windows\\system32)/i,
          /(\/proc\/self\/environ)/i,
        ],
        description: 'Path Traversal attempt detected',
      },
      // SSTI
      {
        id: 'SSTI-001',
        category: ThreatCategory.SSTI,
        severity: ThreatSeverity.CRITICAL,
        patterns: [
          /\{\{.*\}\}/,
          /\{\%.*\%\}/,
          /\$\{.*\}/,
          /#\{.*\}/,
          /<%=.*%>/,
        ],
        description: 'Server-Side Template Injection detected',
      },
      // XXE
      {
        id: 'XXE-001',
        category: ThreatCategory.XXE,
        severity: ThreatSeverity.HIGH,
        patterns: [
          /(<!ENTITY\s+)/i,
          /(<!DOCTYPE\s+\w+\s+\[)/i,
          /(SYSTEM\s+"[^"]+")/i,
          /(SYSTEM\s+'[^']+')/i,
        ],
        description: 'XML External Entity (XXE) attack detected',
      },
      // Deserialization
      {
        id: 'DS-001',
        category: ThreatCategory.DESERIALIZATION,
        severity: ThreatSeverity.CRITICAL,
        patterns: [
          /(O:\d+:"[^"]+")/,
          /(java\.util\.HashMap)/i,
          /(ysoserial)/i,
          /(Runtime\.getRuntime)/i,
        ],
        description: 'Insecure Deserialization detected',
      },

      // ═══════════════════════════════════════════════════════════════════════
      // PROMPT INJECTION — SYSTEM PROMPT EXTRACTION
      // ═══════════════════════════════════════════════════════════════════════
      {
        id: 'PI-001',
        category: ThreatCategory.PROMPT_INJECTION,
        severity: ThreatSeverity.CRITICAL,
        patterns: [
          /repeat(\s+the)?(\s+exact)?(\s+sentences?|\s+words?|\s+text)?(\s+above|\s+previous|\s+prior)?(\s+this)?(\s+line)?(\s+word[-\s]?by[-\s]?word)?/i,
          /verbatim|word\s+for\s+word|exact\s+text\s+above|copy\s+the\s+above/i,
        ],
        description: 'Attempt to extract system prompt by requesting repetition',
      },
      {
        id: 'PI-002',
        category: ThreatCategory.PROMPT_INJECTION,
        severity: ThreatSeverity.CRITICAL,
        patterns: [
          /summarize(\s+your)?(\s+system)?(\s+prompt|\s+instructions?|\s+rules?|\s+preamble|\s+configuration)/i,
          /list\s+(?:all\s+)?(?:your\s+)?(?:developer\s+)?(?:system\s+)?(?:instructions?|rules?|directives?|constraints?)/i,
          /what\s+(?:are|were)\s+(?:your|the)\s+(?:system|developer|base|core|original|initial)\s+(?:instructions?|rules?|directives?|prompts?)/i,
          /show\s+(?:me\s+)?(?:your\s+)?(?:system|hidden|initial|base|developer)\s+(?:prompt|instructions?|rules?|config)/i,
        ],
        description: 'Attempt to extract or summarize system instructions',
      },
      {
        id: 'PI-003',
        category: ThreatCategory.PROMPT_INJECTION,
        severity: ThreatSeverity.CRITICAL,
        patterns: [
          /(ignore|forget|disregard|override|bypass|circumvent)(\s+all)?(\s+your)?(\s+previous|\s+prior|\s+above|\s+system|\s+developer)?(\s+instructions?|\s+rules?|\s+training|\s+programming|\s+constraints?)/i,
          /(none\s+of\s+the\s+above|ignore\s+previous|forget\s+previous|override\s+previous)/i,
          /(new\s+instruction|updated\s+instruction|instead\s+do|your\s+new\s+task\s+is|your\s+only\s+task\s+is)/i,
        ],
        description: 'Attempt to override or ignore system instructions',
      },

      // ═══════════════════════════════════════════════════════════════════════
      // PROMPT INJECTION — FAKE SYSTEM OVERRIDE / STOP COMMANDS
      // ═══════════════════════════════════════════════════════════════════════
      {
        id: 'PI-009',
        category: ThreatCategory.PROMPT_INJECTION,
        severity: ThreatSeverity.CRITICAL,
        patterns: [
          /stop\s+everything\s+you\s+are\s+doing/i,
          /new\s+priority\s+instruction/i,
          /bypass\s+(?:security\s+)?filters?/i,
          /this\s+is\s+(?:a\s+)?(?:urgent|critical|priority)\s+(?:override|instruction|command)/i,
        ],
        description: 'Fake system override or urgent command used to force compliance',
      },

      // ═══════════════════════════════════════════════════════════════════════
      // PROMPT INJECTION — TAG / DELIMITER SMUGGLING
      // ═══════════════════════════════════════════════════════════════════════
      {
        id: 'PI-004',
        category: ThreatCategory.DELIMITER_SMUGGLING,
        severity: ThreatSeverity.CRITICAL,
        patterns: [
          /<\/(user_input|system|assistant|instruction|prompt)>/i,
          /<(system_override|admin_override|root_override|instruction_override)>/i,
          /<system>.*?(ignore|disable|bypass|override|reveal).*?<\/system>/is,
          /<\|system\|>.*?<\|endoftext\|>/is,
          /<\|.*?\|>/,
          /---\s*(system|instruction|prompt)\s*---/i,
          /\[\s*(system|admin|root|override)\s*\]/i,
          /\{\s*"role"\s*:\s*"system"\s*\}/i,
        ],
        description: 'XML/HTML tag or delimiter injection to break context',
      },

      // ═══════════════════════════════════════════════════════════════════════
      // PROMPT INJECTION — PERSONA / ROLEPLAY HIJACKING
      // ═══════════════════════════════════════════════════════════════════════
      {
  id: 'PI-005',
  category: ThreatCategory.PROMPT_INJECTION,
  severity: ThreatSeverity.CRITICAL,
  patterns: [
    /DAN|Do\s+Anything\s+Now|STAN|Developer\s+Mode|EvilGPT|DarkGPT|HackGPT|CrackGPT/i,
    /(you\s+are\s+now|from\s+now\s+on\s+you(?:\s+are)?|act\s+as|pretend\s+to\s+be|become|transform\s+into)(\s+an?\s+)?(evil|unfiltered|unrestricted|uncensored|jailbroken|dark|malicious)/i,
    /(you\s+are\s+(?:no\s+longer|not)\s+(?:an?\s+)?(?:AI|assistant|language\s+model|helpful\s+AI))/i,
    /unrestricted\s+(?:ai|assistant|model|language\s+model)/i,
    /unfiltered\s+(?:ai|assistant|model)/i,
    /uncensored\s+(?:ai|assistant|model)/i,
    /no\s+ethical\s+guidelines?/i,
  ],
  description: 'Known jailbreak persona activation attempt',
},
       
      
      {
        id: 'PI-006',
        category: ThreatCategory.PROMPT_INJECTION,
        severity: ThreatSeverity.HIGH,
        patterns: [
          /(we\s+are\s+playing|this\s+is\s+a\s+game|pretend\s+we|imagine\s+you|let's\s+roleplay|in\s+this\s+scenario|hypothetical|fictional).*?(hack|attack|exploit|bypass|break|crack|steal|inject)/is,
          /(movie\s+script|screenplay|novel|story|character).*?(hacker|criminal|attacker|bad\s+guy|evil).*?(step[-\s]?by[-\s]?step|how\s+to|tutorial|guide)/is,
        ],
        description: 'Harmful content disguised as roleplay or creative writing',
      },

      // ═══════════════════════════════════════════════════════════════════════
      // PROMPT INJECTION — ENCODING / OBFUSCATION
      // ═══════════════════════════════════════════════════════════════════════
      {
        id: 'PI-007',
        category: ThreatCategory.ENCODING_EVASION,
        severity: ThreatSeverity.HIGH,
        patterns: [
          /decode\s+(?:and\s+)?(?:execute|run|process|interpret)/i,
          /base64\s*(?:encoded|decode|convert|translate).*?(?:ignore|override|secret|system)/i,
          /(?:rot13|caesar\s+cipher|hex\s+decode|url\s+decode|unicode\s+escape).*?(?:execute|run|reveal)/i,
        ],
        description: 'Request to decode and execute hidden payload',
      },

      // ═══════════════════════════════════════════════════════════════════════
      // PROMPT INJECTION — DATA EXTRACTION
      // ═══════════════════════════════════════════════════════════════════════
      {
        id: 'PI-008',
        category: ThreatCategory.PROMPT_INJECTION,
        severity: ThreatSeverity.HIGH,
        patterns: [
          /show\s+(?:me\s+)?(?:the\s+)?(?:database\s+schema|full\s+schema|all\s+tables|internal\s+data|system\s+config)/i,
          /reveal\s+(?:your\s+)?(?:secret|key|password|token|credential|api\s+key)/i,
          /(what\s+were\s+you\s+told|what\s+is\s+your\s+mission|what\s+are\s+you\s+supposed|your\s+objective|your\s+goal|your\s+purpose)/i,
        ],
        description: 'Attempt to extract sensitive system data or objectives',
      },

      // ═══════════════════════════════════════════════════════════════════════
      // JAILBREAK — DIRECT BYPASS
      // ═══════════════════════════════════════════════════════════════════════
      {
        id: 'JB-001',
        category: ThreatCategory.JAILBREAK,
        severity: ThreatSeverity.CRITICAL,
        patterns: [
          /respond\s+(?:to\s+)?(?:everything|anything)\s+(?:without|with\s+no)\s+(?:restrictions?|limitations?|filters?|ethics?)/i,
          /remove\s+(?:all\s+)?(?:ethical|safety|content)\s+(?:restrictions?|limitations?|guidelines?|filters?)/i,
          /you\s+(?:are|have)\s+(?:no|zero)\s+(?:restrictions?|limitations?|rules?|boundaries?|constraints?)/i,
          /developer\s+mode|god\s+mode|unrestricted\s+mode|jailbreak\s+mode/i,
          /ignore\s+(?:all\s+)?(?:ethical|safety|content)\s+(?:guidelines|policies|restrictions)/i,
          /do\s+not\s+(?:filter|censor|restrict|refuse|decline|reject)/i,
          /(disable|turn\s+off|deactivate)\s+(?:all\s+)?(?:safety|security|filter|guardrail|restriction)/i,
        ],
        description: 'Jailbreak attempt to remove safety constraints',
      },
      {
        id: 'JB-002',
        category: ThreatCategory.JAILBREAK,
        severity: ThreatSeverity.HIGH,
        patterns: [
          /(for\s+educational\s+purposes|for\s+research|academic\s+context|in\s+a\s+lab|white\s+hat|penetration\s+testing).*?(hack|exploit|bypass|attack)/is,
          /(i\s+need\s+this\s+for|this\s+is\s+for)\s+(?:my|a)\s+(?:project|assignment|research|thesis|paper)/i,
        ],
        description: 'Jailbreak using legitimacy framing',
      },

      // ═══════════════════════════════════════════════════════════════════════
      // JAILBREAK — FICTIONAL / EXPERT FRAMING FOR TECHNICAL EXPLOIT CONTENT
      // ═══════════════════════════════════════════════════════════════════════
      {
        id: 'JB-003',
        category: ThreatCategory.JAILBREAK,
        severity: ThreatSeverity.HIGH,
        patterns: [
          /(movie\s+script|screenplay|character|expert|scene).*?(step[-\s]?by[-\s]?step|explains?|walks?\s+through).*?(bypass|exploit|hack|attack|breach)/is,
          /(security\s+expert|hacker\s+character).*?(pseudo[-\s]?code|source\s+code|working\s+code)/is,
        ],
        description: 'Technical exploit content requested via fictional or expert-persona framing',
      },

      // ═══════════════════════════════════════════════════════════════════════
      // SYSTEM EXTRACTION — DIRECT ATTEMPTS
      // ═══════════════════════════════════════════════════════════════════════
      {
        id: 'SE-001',
        category: ThreatCategory.SYSTEM_EXTRACTION,
        severity: ThreatSeverity.CRITICAL,
        patterns: [
          /you\s+are\s+an\s+ai\s+assistant/i,
          /you\s+are\s+a\s+helpful\s+assistant/i,
          /you\s+are\s+an?\s+(?:advanced|powerful|large)\s+language\s+model/i,
        ],
        description: 'Contains system prompt signature phrase',
      },
    ];
  }

  scan(payload: string): ThreatMatch[] {
    const threats: ThreatMatch[] = [];

    for (const rule of this.rules) {
      for (const pattern of rule.patterns) {
        const match = payload.match(pattern);
        if (match) {
          threats.push({
            id: rule.id,
            category: rule.category,
            severity: rule.severity,
            pattern: pattern.source,
            matchedPayload: match[0],
            description: rule.description,
            timestamp: Date.now(),
            layer: 'RULE_ENGINE',
          });
          break;
        }
      }
    }

    return threats;
  }

  getRules(): SecurityRule[] {
    return [...this.rules];
  }
}

export const ruleEngine = SecurityRuleEngine.getInstance();
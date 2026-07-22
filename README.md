# 🛡️ AI Security WAF

A real-time AI-powered Web Application Firewall that detects and blocks malicious payloads including SQL injection, XSS, command injection, and LLM-specific attacks like prompt injection and jailbreaks.

## Features

- **Multi-Layer Detection**
  - Signature-based rule engine (regex pattern matching)
  - Entropy/perplexity analysis for encoded or obfuscated payloads
  - Embedding-based semantic detection for system prompt leakage

- **Threat Categories Covered**
  - SQL Injection (basic, UNION-based, blind/time-based)
  - NoSQL Injection
  - Cross-Site Scripting (XSS)
  - Command Injection
  - Path Traversal
  - Server-Side Template Injection (SSTI)
  - XML External Entity (XXE)
  - Insecure Deserialization
  - Prompt Injection & Jailbreak attempts (DAN, roleplay hijacking, fictional-framing exploits)
  - Delimiter/tag smuggling
  - System prompt extraction

- **Payload Normalization**
  Automatically decodes HTML entities, Unicode/hex escapes, URL encoding, and multi-layer Base64 before scanning — catching obfuscated attacks that bypass naive filters.

- **Live Dashboard**
  Real-time scan results, threat log, and an interactive attacker sandbox with pre-loaded test payloads for demonstration.

## Tech Stack

- **Framework:** Next.js (App Router)
- **Language:** TypeScript
- **Styling:** Tailwind CSS
- **Detection Engine:** Custom rule engine + entropy scoring + embedding similarity

## Getting Started

```bash
git clone https://github.com/iqrazulfiqar7373-coder/ai-security-waf.git
cd ai-security-waf
npm install
npm run dev

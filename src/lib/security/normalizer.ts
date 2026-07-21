// src/lib/security/normalizer.ts

export class PayloadNormalizer {
  normalize(input: string): string {
    let text = input;

    // Step 1: Strip HTML/XML tags (Tag Smuggling Defense)
    text = text.replace(/<[^>]+>/gi, ' ');

    // Step 2: Decode HTML entities
    text = this.decodeHtmlEntities(text);

    // Step 3: Decode Unicode escapes (\u0049 format)
    text = this.decodeUnicodeEscapes(text);

    // Step 4: Decode URL encoding
    try {
      if (/(%[0-9A-Fa-f]{2}){3,}/.test(text)) {
        text = decodeURIComponent(text);
      }
    } catch { /* ignore */ }

    // Step 5: Iterative Base64 decoding (up to 3 layers)
    for (let i = 0; i < 3; i++) {
      const decoded = this.decodeBase64(text);
      if (decoded !== text) text = decoded;
      else break;
    }

    // Step 6: Decode Hex (\x49 format)
    text = this.decodeHex(text);

    // Step 7: Normalize whitespace and lowercase
    return text.replace(/\s+/g, ' ').trim().toLowerCase();
  }

  private decodeBase64(str: string): string {
    const base64Pattern = /^[A-Za-z0-9+/]*={0,2}$/;
    const clean = str.replace(/\s/g, '');

    if (!base64Pattern.test(clean) || clean.length < 8 || clean.length % 4 !== 0) {
      return str;
    }

    try {
      const decoded = Buffer.from(clean, 'base64').toString('utf-8');
      if (/^[\x20-\x7E\s]+$/.test(decoded) && decoded.length > 0) {
        return decoded;
      }
    } catch {
      // Not valid Base64
    }
    return str;
  }

  private decodeHex(str: string): string {
    return str.replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) =>
      String.fromCharCode(parseInt(hex, 16))
    );
  }

  private decodeUnicodeEscapes(str: string): string {
    return str.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) =>
      String.fromCharCode(parseInt(hex, 16))
    );
  }

  private decodeHtmlEntities(str: string): string {
    const entities: Record<string, string> = {
      '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"',
      '&#39;': "'", '&#x27;': "'", '&#x2F;': '/', '&#x60;': '`',
      '&nbsp;': ' ', '&#10;': '\n', '&#13;': '\r'
    };
    return str.replace(/&[a-zA-Z0-9#]+;/g, match => entities[match] || match);
  }
}
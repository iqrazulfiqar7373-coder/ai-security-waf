// src/app/api/scan/route.ts

import { NextRequest, NextResponse } from 'next/server';
import { v4 as uuidv4 } from 'uuid';
import { aiScanner } from '@/lib/security/aiscanner';
import { ScanResponse } from '@/types/security';

export async function POST(req: NextRequest) {
  const startTime = Date.now();
  try {
    const body = await req.json();
    const { payload } = body;

    if (!payload || typeof payload !== 'string') {
      return NextResponse.json(
        { error: 'Payload is required and must be a string' },
        { status: 400 }
      );
    }

    const result = aiScanner.scan(payload);
    const processingTime = Date.now() - startTime;

    const response: ScanResponse = {
      id: uuidv4(),
      blocked: !result.safe,
      threats: result.threats,
      reason: result.reason,
      normalizedPayload: result.metadata?.normalizedText,
      processingTime,
      aiAnalysis: {
        intent: result.safe
          ? 'BENIGN'
          : result.confidence > 0.7
          ? 'MALICIOUS'
          : 'SUSPICIOUS',
        confidence: result.confidence,
        reasoning: result.reason || 'No threats detected in this payload.',
      },
    };

    return NextResponse.json(response);
  } catch (error) {
    console.error('Scan error:', error);
    return NextResponse.json(
      { error: 'Internal server error during scan' },
      { status: 500 }
    );
  }
}

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const mode = searchParams.get('mode');

  if (mode === 'test') {
    const report = await aiScanner.runRedTeamTests();
    return NextResponse.json({ report });
  }

  return NextResponse.json({
    message: 'AI Security Scanner API',
    endpoints: {
      POST: '/api/scan - Scan a payload',
      GET: '/api/scan?mode=test - Run red-team tests',
    },
  });
}
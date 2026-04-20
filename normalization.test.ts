// normalization.test.ts

import { describe, it, expect } from 'vitest';
import { normalize, signEvent } from './normalization.js';
import { InMemoryKeyProvider, verifyObject } from './signing.js';

describe('normalization', () => {
  it('normalizes extraction output into signed facts', async () => {
    const keys = await InMemoryKeyProvider.generate();

    const event = await signEvent(
      {
        source: 'mentor',
        action: 'utterance_captured',
        timestamp: new Date().toISOString(),
      },
      keys
    );

    const extraction = {
      facts: [
        {
          id: 'fact_1',
          type: 'goal',
          statement: 'User wants to build Inner Portal at global scale.',
          confidence: 0.91,
        },
        {
          id: 'fact_2',
          type: 'project',
          statement: 'User is building SoVereign.',
          confidence: 0.95,
        },
      ],
    };

    const result = await normalize(
      extraction,
      { sourceEventIds: [event.id] },
      keys
    );

    expect(result).toBeDefined();
    expect(Array.isArray(result.facts)).toBe(true);
    expect(Array.isArray(result.rejected)).toBe(true);
    expect(result.facts.length).toBe(2);
    expect(result.rejected.length).toBe(0);

    for (const fact of result.facts) {
      expect(fact.id).toBeTruthy();
      expect(fact.signature).toBeTruthy();

      const verified = await verifyObject(fact, fact.signature, keys);
      expect(verified).toBe(true);
    }
  });

  it('rejects malformed facts instead of crashing', async () => {
    const keys = await InMemoryKeyProvider.generate();

    const extraction = {
      facts: [
        {
          id: 'fact_valid',
          type: 'goal',
          statement: 'User wants to grow the platform.',
          confidence: 0.9,
        },
        {
          id: '',
          type: 'goal',
          statement: 'Broken fact with empty id.',
          confidence: 0.8,
        },
        {
          type: 'emotion',
          statement: 'Missing id should be rejected.',
          confidence: 0.7,
        },
      ],
    };

    const result = await normalize(
      extraction,
      { sourceEventIds: ['evt_dev_1'] },
      keys
    );

    expect(result.facts.length).toBe(1);
    expect(result.rejected.length).toBeGreaterThanOrEqual(1);
  });

  it('attaches sourceEventIds to normalized facts', async () => {
    const keys = await InMemoryKeyProvider.generate();

    const extraction = {
      facts: [
        {
          id: 'fact_linked',
          type: 'insight',
          statement: 'User responds well to structured reflection.',
          confidence: 0.88,
        },
      ],
    };

    const result = await normalize(
      extraction,
      { sourceEventIds: ['evt_123', 'evt_456'] },
      keys
    );

    expect(result.facts.length).toBe(1);

    const fact = result.facts[0] as Record<string, unknown>;

    const sourceEventIds =
      (fact.sourceEventIds as string[] | undefined) ??
      (fact.source_event_ids as string[] | undefined);

    expect(sourceEventIds).toEqual(['evt_123', 'evt_456']);
  });

  it('returns empty arrays when extraction contains no facts', async () => {
    const keys = await InMemoryKeyProvider.generate();

    const extraction = {
      facts: [],
    };

    const result = await normalize(
      extraction,
      { sourceEventIds: ['evt_empty'] },
      keys
    );

    expect(result.facts).toEqual([]);
    expect(result.rejected).toEqual([]);
  });
});

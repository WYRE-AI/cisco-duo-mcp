import type { CallToolResult } from '../tools/types.js';

/** Extracts the text of the first content block, failing loudly if it isn't text. */
export function textOf(result: CallToolResult): string {
  const block = result.content?.[0];
  if (!block || block.type !== 'text') {
    throw new Error(`Expected a text content block, got: ${JSON.stringify(block)}`);
  }
  return block.text;
}

/** Builds a Response whose body is JSON, matching Duo's `{ stat, response, metadata? }` envelope shape. */
export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

/** Wraps a value in Duo's standard `{ stat: 'OK', response }` single-object envelope. */
export function duoObject<T>(response: T): { stat: 'OK'; response: T } {
  return { stat: 'OK', response };
}

/** Wraps an array in Duo's standard `{ stat: 'OK', response, metadata }` list envelope. */
export function duoList<T>(
  response: T[],
  metadata: Record<string, unknown> = {}
): { stat: 'OK'; response: T[]; metadata: Record<string, unknown> } {
  return { stat: 'OK', response, metadata };
}

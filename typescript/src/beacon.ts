/**
 * Публичный маяк — нижняя граница времени.
 *
 * Значение раунда невозможно было знать заранее, поэтому всё, что стоит в цепи
 * после записи маяка, создано после его публикации. Вместе с пломбой это даёт
 * двустороннюю границу: не раньше маяка, не позже пломбы.
 *
 * Недоступность маяка не ошибка: отрезок пишется без него, нижней границы в
 * выписке просто не будет.
 */

export interface BeaconValue {
  source: string;
  round: number;
  value: Buffer;
  fetchedAt: number;
}

const DRAND_QUICKNET =
  "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";

const SOURCES: Record<string, { name: string; url: string }> = {
  drand: {
    name: "drand:quicknet",
    url: `https://api.drand.sh/${DRAND_QUICKNET}/public/latest`,
  },
};

export async function fetchBeacon(source = "drand",
                                  timeoutMs = 2000): Promise<BeaconValue | null> {
  const entry = SOURCES[source];
  if (!entry) return null;
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const r = await fetch(entry.url, { signal: ctl.signal });
    if (!r.ok) return null;
    const d = (await r.json()) as { round: number; randomness: string };
    return {
      source: entry.name,
      round: d.round,
      value: Buffer.from(d.randomness, "hex"),
      fetchedAt: Date.now(),
    };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Время публикации раунда. Для quicknet: генезис 1692803367, шаг 3 с.
 * Полная проверка подписи BLS выходит за рамки версии 1 и отмечается в
 * выписке как непроверенная.
 */
export function lowerBoundMs(round: number, source = "drand:quicknet"): number | null {
  if (source !== "drand:quicknet") return null;
  return (1692803367 + (round - 1) * 3) * 1000;
}

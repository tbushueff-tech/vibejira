// Entry order of the reference's HashMap(32), for its bounded property sets.
// Replay insertions rather than sorting by hash: resize preserves chain order.
export function javaPropertyEntries(data) {
  let buckets = Array.from({ length: 32 }, () => []);
  let size = 0;
  const hash = key => {
    let value = 0;
    for (let i = 0; i < key.length; i++) value = (Math.imul(value, 31) + key.charCodeAt(i)) | 0;
    return (value ^ (value >>> 16)) >>> 0;
  };
  const resize = () => {
    const next = Array.from({ length: buckets.length * 2 }, () => []);
    for (const chain of buckets) for (const entry of chain)
      next[entry.hash & (next.length - 1)].push(entry);
    buckets = next;
  };
  for (const [key, value] of data) {
    const h = hash(key), chain = buckets[h & (buckets.length - 1)];
    chain.push({ key, value, hash: h });
    size++;
    // Java treeifyBin expands small tables first. The product schema has
    // fewer colliding keys than would require tree bins at capacity >= 64.
    if (chain.length >= 9 && buckets.length < 64) resize();
    if (size > buckets.length * 0.75) resize();
  }
  return buckets.flatMap(chain => chain.map(({ key, value }) => [key, value]));
}

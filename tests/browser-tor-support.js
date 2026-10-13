// Controlled private engine contract for Keys custody tests. This is not a Tor
// implementation and makes no claim about Snowflake or public-network access.
export function fixture() {
  return {
    calls: 0, stops: 0, aborts: 0, matched: false, wiped: false,
    identity: null, scope: null, signal: null, snowflake: false,
    held: false, pending: null,
  };
}

function inspect(identity, scope, verify, f) {
  let seed;
  try {
    seed = identity.onionKey(scope);
    if (!(seed instanceof Uint8Array) || seed.length !== 32) return false;
    return verify(seed) === true;
  } finally {
    if (seed instanceof Uint8Array) {
      seed.fill(0);
      if (f) f.wiped = seed.every(byte => byte === 0);
    }
  }
}

export function factory(f, verify) {
  return options => {
    f.calls++;
    // Retain the capability deliberately, to test refusal after Rust custody
    // closes. No returned seed is retained in this fixture or backend.
    f.identity = options.identity;
    f.scope = options.scope.slice();
    f.signal = options.signal;
    f.snowflake = options.snowflake === true;
    f.signal.addEventListener('abort', () => { f.aborts++; }, {once: true});
    f.matched = inspect(f.identity, options.scope, verify, f);
    if (!f.matched) throw new Error('fixture identity mismatch');
    let stopped = false;
    const backend = {
      scheme: 'tor',
      health() { return stopped ? 'Stopped' : 'Ready'; },
      stop() { f.stops++; stopped = true; },
    };
    if (!f.held) return backend;
    return new Promise(resolve => { f.pending = () => resolve(backend); });
  };
}

export function count(f, name) { return f[name]; }
export function flag(f, name) { return f[name] === true; }
export function scope(f) { return f.scope.slice(); }
export function aborted(f) { return f.signal?.aborted === true; }
export function hold(f) { f.held = true; }
export function release(f) {
  const pending = f.pending;
  if (!pending) throw new Error('fixture factory is not pending');
  f.pending = null;
  pending();
}
export function matches(f, supplied, verify) {
  return inspect(f.identity, supplied, verify);
}
export function refuses(f, supplied) {
  let seed;
  try {
    seed = f.identity.onionKey(supplied);
    return false;
  } catch {
    return true;
  } finally {
    if (seed instanceof Uint8Array) seed.fill(0);
  }
}
export function afterTurn(callback) {
  // Drain the promises created by one Rust poll; elapsed time is not evidence.
  setTimeout(callback, 0);
}

'use strict';

// probe.py injects a frozen configuration into a mode-0600 temporary copy.
const PALMOD_CONFIG = __PALMOD_CONFIG__;

function emit(record) {
  console.log(JSON.stringify(record));
}

function bytesMatch(address, expectedPattern) {
  if (expectedPattern === null || expectedPattern.length === 0) {
    return true;
  }
  const actual = new Uint8Array(address.readByteArray(expectedPattern.length));
  for (let index = 0; index < expectedPattern.length; index++) {
    const expected = expectedPattern[index];
    if (expected !== null && actual[index] !== expected) {
      return false;
    }
  }
  return true;
}

function main() {
  if (PALMOD_CONFIG.mode !== 'observe') {
    if (!PALMOD_CONFIG.mutation_allowed || !PALMOD_CONFIG.crash_risk_accepted) {
      throw new Error('mutation mode requires both independent opt-ins');
    }
    throw new Error('no mutation-capable agent is shipped in this research slice');
  }

  const module = Process.getModuleByName(PALMOD_CONFIG.module_name);
  let emitted = 0;
  const listeners = [];
  for (const hook of PALMOD_CONFIG.hooks) {
    if (!Number.isSafeInteger(hook.rva) || hook.rva < 0 || hook.rva >= module.size) {
      throw new Error(`RVA outside module: ${hook.name} ${hook.rva}`);
    }
    const address = module.base.add(hook.rva);
    if (!bytesMatch(address, hook.expected_pattern)) {
      throw new Error(`runtime anchor mismatch at ${hook.name} (${address})`);
    }
    listeners.push(
      Interceptor.attach(address, {
        onEnter() {
          if (emitted >= PALMOD_CONFIG.max_events) {
            return;
          }
          emitted += 1;
          const event = {
            address: address.toString(),
            event: 'enter',
            hook: hook.name,
            sequence: emitted,
            thread_id: this.threadId,
          };
          if (PALMOD_CONFIG.backtrace_depth > 0) {
            event.backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
              .slice(0, PALMOD_CONFIG.backtrace_depth)
              .map((item) => DebugSymbol.fromAddress(item).toString());
          }
          emit(event);
        },
      })
    );
  }
  emit({
    event: 'ready',
    hooks: PALMOD_CONFIG.hooks.map((hook) => hook.name),
    module_base: module.base.toString(),
    module_name: module.name,
    mutation_allowed: false,
    profile_id: PALMOD_CONFIG.profile_id,
  });
}

setImmediate(main);

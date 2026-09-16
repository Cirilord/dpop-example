export type DpopLog = {
  start(): void;
  ok(title: string, details?: string): void;
  fail(title: string, details?: string): void;
  finish(message?: string): void;
};

export const silentDpopLog: DpopLog = {
  start() {},
  ok() {},
  fail() {},
  finish() {},
};

export function createDpopLog(enabled: boolean): DpopLog {
  function write(line = ''): void {
    if (enabled) {
      console.log(line);
    }
  }

  return {
    start() {
      write('[DPoP] Validating request');
      write();
    },
    ok(title, details) {
      write(`✓ ${title}`);
      if (details) {
        for (const line of details.split('\n')) {
          write(line);
        }
      }
      write();
    },
    fail(title, details) {
      write(`✗ ${title}`);
      if (details) {
        for (const line of details.split('\n')) {
          write(line);
        }
      }
      write();
    },
    finish(message) {
      write('--------------------------------');
      write();
      write(message ?? 'DPoP validation succeeded');
      write();
    },
  };
}

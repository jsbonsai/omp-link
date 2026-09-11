// Hand-written types for command-registry.mjs. There is no build step: the
// `.mjs` runs as-is under bare `node` for bin/*.mjs, and NodeNext resolves this
// declaration file for `import ... from "./src/command-registry.mjs"` in TS.

export interface ExitCodes {
  readonly OK: 0;
  readonly ERROR: 1;
  readonly USAGE: 2;
  readonly UNAVAILABLE: 3;
  readonly REFUSED: 4;
}

export declare const EXIT: ExitCodes;

export declare function getVersion(): string;

export type FlagKind = "boolean" | "value";

export type CommandSurface = "agent" | "cli" | "both";

export interface FlagSpec {
  readonly name: string;
  readonly kind: FlagKind;
  readonly summary: string;
  readonly placeholder: string | null;
}

/** A global flag also records the surface that actually honours it. */
export interface GlobalFlagSpec {
  readonly name: string;
  readonly kind: FlagKind;
  readonly surface: CommandSurface;
  readonly summary: string;
}

export interface CommandSpec {
  readonly name: string;
  readonly aliases: readonly string[];
  readonly surface: CommandSurface;
  readonly usage: string;
  readonly summary: string;
  readonly details: readonly string[];
  readonly flags: readonly FlagSpec[];
  readonly minArgs: number;
  readonly maxArgs: number;
  readonly hubOnly: boolean;
}

export declare const GLOBAL_FLAGS: readonly GlobalFlagSpec[];

/** The global flags a surface honours; the parser rejects the others there. */
export declare function globalFlagsFor(surface: CommandSurface): readonly GlobalFlagSpec[];

export declare const COMMANDS: readonly CommandSpec[];

/** Removed verb -> replacement command name, or null when there is none. */
export declare const REMOVED_COMMANDS: Readonly<Record<string, string | null>>;

export declare function findCommand(nameOrAlias: string): CommandSpec | null;

export interface ParseOptions {
  /** Which surface is parsing; decides usage prefix and surface enforcement. Default "cli". */
  readonly surface?: CommandSurface;
  /** Command assumed when the argv has no leading verb. Default "status". */
  readonly defaultCommand?: string;
}

export interface Invocation {
  /** Resolved canonical command name, or null when the verb could not be resolved. */
  readonly command: string | null;
  readonly positionals: readonly string[];
  /**
   * Flag values keyed by camelCased long name without dashes:
   * `--no-input` -> `noInput`, `--verbose` -> `verbose`, `--for 10m` -> `for`.
   * Boolean flags are `true` when present and absent otherwise.
   */
  readonly flags: Readonly<Record<string, string | boolean>>;
  /** Human-readable usage error, or null when the invocation is valid. */
  readonly error: string | null;
}

/**
 * Parse argv (program name already stripped) against the registry.
 * Unknown flags, unknown verbs, removed verbs, bad arity and wrong-surface
 * calls all come back as `error`; nothing is silently ignored.
 */
export declare function parseInvocation(argv: readonly string[], options?: ParseOptions): Invocation;

/**
 * Full help when called with no command name; detailed help for one command otherwise.
 * `surface` (default "cli") decides which global flags are advertised.
 */
export declare function renderHelp(name?: string | null, surface?: CommandSurface): string;

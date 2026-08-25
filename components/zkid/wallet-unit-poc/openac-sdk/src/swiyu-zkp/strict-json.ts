export type StrictJsonNode =
  | StrictJsonObject
  | StrictJsonArray
  | StrictJsonString
  | StrictJsonNumber
  | StrictJsonLiteral;

export interface StrictJsonProperty {
  key: string;
  /** Offset of the key's opening quote in the decoded compact JSON bytes. */
  keyStart: number;
  value: StrictJsonNode;
}

export interface StrictJsonObject {
  kind: "object";
  start: number;
  end: number;
  properties: ReadonlyMap<string, StrictJsonProperty>;
}

export interface StrictJsonArray {
  kind: "array";
  start: number;
  end: number;
  items: readonly StrictJsonNode[];
}

export interface StrictJsonString {
  kind: "string";
  start: number;
  end: number;
  value: string;
  /** Bytes between quotes, before JSON escape decoding. */
  rawContent: string;
}

export interface StrictJsonNumber {
  kind: "number";
  start: number;
  end: number;
  raw: string;
}

export interface StrictJsonLiteral {
  kind: "literal";
  start: number;
  end: number;
  value: boolean | null;
}

/**
 * Parse the compact, ASCII JSON subset accepted by the fixed Circom profile.
 *
 * JSON.parse silently keeps the last duplicate key. This parser instead keeps
 * structural byte offsets and rejects duplicates in every object. Whitespace
 * outside strings and non-ASCII bytes are rejected because the circuit binds
 * exact compact byte positions, not a host-side reserialization.
 */
export function parseStrictCompactJson(source: string): StrictJsonNode {
  assertAscii(source, "JSON");
  const parser = new StrictJsonParser(source);
  const value = parser.parseValue();
  if (!parser.atEnd()) {
    throw new Error(`Unexpected byte at offset ${parser.offset}`);
  }
  rejectStringEscapes(value);
  return value;
}

/** Parse general JSON while retaining offsets and rejecting duplicate keys. */
export function parseJsonWithUniqueKeys(source: string): StrictJsonNode {
  const parser = new StrictJsonParser(source, true);
  const value = parser.parseValue();
  if (!parser.atEnd()) {
    throw new Error(`Unexpected byte at offset ${parser.offset}`);
  }
  return value;
}

export function requireObject(
  node: StrictJsonNode,
  path: string,
): StrictJsonObject {
  if (node.kind !== "object") {
    throw new Error(`${path} must be an object`);
  }
  return node;
}

export function requireArray(
  node: StrictJsonNode,
  path: string,
): StrictJsonArray {
  if (node.kind !== "array") {
    throw new Error(`${path} must be an array`);
  }
  return node;
}

export function requireString(
  node: StrictJsonNode,
  path: string,
): StrictJsonString {
  if (node.kind !== "string") {
    throw new Error(`${path} must be a string`);
  }
  // Security strings are wired as literal circuit bytes. Escaped aliases are
  // intentionally excluded from this small profile.
  if (node.rawContent !== node.value) {
    throw new Error(`${path} must not use JSON escapes`);
  }
  return node;
}

/**
 * Read a string from a normal JSON transport boundary.
 *
 * Unlike requireString, this accepts JSON escape sequences because the decoded
 * value, rather than the source spelling, is the transport contract.
 */
export function requireDecodedString(
  node: StrictJsonNode,
  path: string,
): StrictJsonString {
  if (node.kind !== "string") {
    throw new Error(`${path} must be a string`);
  }
  return node;
}

export function requireProperty(
  object: StrictJsonObject,
  key: string,
  path: string,
): StrictJsonProperty {
  const property = object.properties.get(key);
  if (!property) {
    throw new Error(`${path}.${key} is required`);
  }
  return property;
}

export function forbidProperty(
  object: StrictJsonObject,
  key: string,
  path: string,
): void {
  if (object.properties.has(key)) {
    throw new Error(`${path}.${key} is forbidden by this profile`);
  }
}

export function requireUnsignedDecimal(
  node: StrictJsonNode,
  path: string,
  maxDigits = 10,
): { raw: string; value: bigint } {
  if (node.kind !== "number" || !/^(0|[1-9][0-9]*)$/.test(node.raw)) {
    throw new Error(`${path} must be a canonical unsigned integer`);
  }
  if (node.raw.length > maxDigits) {
    throw new Error(`${path} exceeds ${maxDigits} decimal digits`);
  }
  return { raw: node.raw, value: BigInt(node.raw) };
}

export function assertAscii(value: string, label: string): void {
  for (let index = 0; index < value.length; index++) {
    if (value.charCodeAt(index) > 0x7f) {
      throw new Error(`${label} must contain ASCII bytes only`);
    }
  }
}

function rejectStringEscapes(node: StrictJsonNode): void {
  if (node.kind === "string") {
    if (node.rawContent !== node.value) {
      throw new Error(`JSON strings must not use escapes at offset ${node.start}`);
    }
    return;
  }
  if (node.kind === "array") {
    for (const item of node.items) rejectStringEscapes(item);
    return;
  }
  if (node.kind === "object") {
    for (const property of node.properties.values()) {
      rejectStringEscapes(property.value);
    }
  }
}

class StrictJsonParser {
  offset = 0;

  constructor(
    private readonly source: string,
    private readonly allowWhitespace = false,
  ) {}

  atEnd(): boolean {
    this.skipWhitespace();
    return this.offset === this.source.length;
  }

  parseValue(): StrictJsonNode {
    this.skipWhitespace();
    const char = this.source[this.offset];
    if (char === "{") return this.parseObject();
    if (char === "[") return this.parseArray();
    if (char === '"') return this.parseString();
    if (char === "t") return this.parseLiteral("true", true);
    if (char === "f") return this.parseLiteral("false", false);
    if (char === "n") return this.parseLiteral("null", null);
    if (char === "-" || (char !== undefined && char >= "0" && char <= "9")) {
      return this.parseNumber();
    }
    if (char !== undefined && /\s/.test(char)) {
      throw new Error(`Whitespace is not allowed at offset ${this.offset}`);
    }
    throw new Error(`Expected a JSON value at offset ${this.offset}`);
  }

  private parseObject(): StrictJsonObject {
    const start = this.offset++;
    const properties = new Map<string, StrictJsonProperty>();
    this.skipWhitespace();
    if (this.source[this.offset] === "}") {
      const end = this.offset++;
      return { kind: "object", start, end, properties };
    }

    while (true) {
      this.skipWhitespace();
      if (this.source[this.offset] !== '"') {
        throw new Error(`Expected an object key at offset ${this.offset}`);
      }
      const keyNode = this.parseString();
      const key = keyNode.value;
      if (keyNode.rawContent !== key) {
        throw new Error(`JSON object keys must not use escapes at offset ${keyNode.start}`);
      }
      if (properties.has(key)) {
        throw new Error(`Duplicate JSON key ${JSON.stringify(key)}`);
      }
      this.skipWhitespace();
      if (this.source[this.offset++] !== ":") {
        throw new Error(`Expected ':' after ${JSON.stringify(key)}`);
      }
      const value = this.parseValue();
      properties.set(key, { key, keyStart: keyNode.start, value });

      this.skipWhitespace();
      const delimiter = this.source[this.offset++];
      if (delimiter === "}") {
        return { kind: "object", start, end: this.offset - 1, properties };
      }
      if (delimiter !== ",") {
        throw new Error(`Expected ',' or '}' at offset ${this.offset - 1}`);
      }
    }
  }

  private parseArray(): StrictJsonArray {
    const start = this.offset++;
    const items: StrictJsonNode[] = [];
    this.skipWhitespace();
    if (this.source[this.offset] === "]") {
      const end = this.offset++;
      return { kind: "array", start, end, items };
    }

    while (true) {
      items.push(this.parseValue());
      this.skipWhitespace();
      const delimiter = this.source[this.offset++];
      if (delimiter === "]") {
        return { kind: "array", start, end: this.offset - 1, items };
      }
      if (delimiter !== ",") {
        throw new Error(`Expected ',' or ']' at offset ${this.offset - 1}`);
      }
    }
  }

  private parseString(): StrictJsonString {
    const start = this.offset;
    this.offset++;
    while (this.offset < this.source.length) {
      const char = this.source[this.offset]!;
      if (char === '"') {
        this.offset++;
        const raw = this.source.slice(start, this.offset);
        let value: unknown;
        try {
          value = JSON.parse(raw);
        } catch (error) {
          throw new Error(
            `Invalid JSON string at offset ${start}: ${error instanceof Error ? error.message : String(error)}`,
          );
        }
        if (typeof value !== "string") {
          throw new Error(`Invalid JSON string at offset ${start}`);
        }
        return {
          kind: "string",
          start,
          end: this.offset - 1,
          value,
          rawContent: raw.slice(1, -1),
        };
      }
      if (char.charCodeAt(0) < 0x20) {
        throw new Error(`Unescaped control byte in string at offset ${this.offset}`);
      }
      if (char === "\\") {
        this.offset++;
        const escaped = this.source[this.offset];
        if (escaped === undefined || !'"\\/bfnrtu'.includes(escaped)) {
          throw new Error(`Invalid JSON escape at offset ${this.offset - 1}`);
        }
        if (escaped === "u") {
          const hex = this.source.slice(this.offset + 1, this.offset + 5);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) {
            throw new Error(`Invalid Unicode escape at offset ${this.offset - 1}`);
          }
          this.offset += 4;
        }
      }
      this.offset++;
    }
    throw new Error(`Unterminated JSON string at offset ${start}`);
  }

  private parseNumber(): StrictJsonNumber {
    const start = this.offset;
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(
      this.source.slice(start),
    );
    if (!match) {
      throw new Error(`Invalid JSON number at offset ${start}`);
    }
    this.offset += match[0].length;
    return { kind: "number", start, end: this.offset - 1, raw: match[0] };
  }

  private parseLiteral(
    token: "true" | "false" | "null",
    value: boolean | null,
  ): StrictJsonLiteral {
    const start = this.offset;
    if (this.source.slice(start, start + token.length) !== token) {
      throw new Error(`Invalid JSON literal at offset ${start}`);
    }
    this.offset += token.length;
    return { kind: "literal", start, end: this.offset - 1, value };
  }

  private skipWhitespace(): void {
    if (!this.allowWhitespace) return;
    while (
      this.source[this.offset] === " " ||
      this.source[this.offset] === "\t" ||
      this.source[this.offset] === "\n" ||
      this.source[this.offset] === "\r"
    ) {
      this.offset++;
    }
  }
}

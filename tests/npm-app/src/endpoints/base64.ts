const BASE64_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const BASE64_DECODE_TABLE = new Map<string, number>(
  Array.from(BASE64_ALPHABET, (char, index) => [char, index]),
);

export function base64ToUint8Array(input: string): Uint8Array {
  let clean = input.replace(/\s/g, "");
  const remainder = clean.length % 4;
  if (remainder !== 0) {
    clean += "=".repeat(4 - remainder);
  }

  const padding = clean.endsWith("==") ? 2 : clean.endsWith("=") ? 1 : 0;
  const output = new Uint8Array((clean.length / 4) * 3 - padding);
  let outputIndex = 0;

  for (let offset = 0; offset < clean.length; offset += 4) {
    const values = [0, 1, 2, 3].map((index) => {
      const char = clean[offset + index];
      if (char === "=") {
        return 0;
      }

      const value = BASE64_DECODE_TABLE.get(char);
      if (value === undefined) {
        throw new Error(`Invalid base64 character: ${char}`);
      }

      return value;
    });

    const bits =
      (values[0] << 18) | (values[1] << 12) | (values[2] << 6) | values[3];

    if (outputIndex < output.length) {
      output[outputIndex++] = (bits >> 16) & 0xff;
    }
    if (outputIndex < output.length) {
      output[outputIndex++] = (bits >> 8) & 0xff;
    }
    if (outputIndex < output.length) {
      output[outputIndex++] = bits & 0xff;
    }
  }

  return output;
}

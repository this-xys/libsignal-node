export function decrypt(
  key: Uint8Array,
  ciphertext: Uint8Array,
  iv: Uint8Array
): Promise<Uint8Array>;

export function encrypt(
  key: Uint8Array,
  plaintext: Uint8Array,
  iv: Uint8Array
): Promise<Buffer>;

export function calculateMAC(key: Buffer, data: Uint8Array): Uint8Array;

export function verifyMAC(
  data: Buffer,
  key: Buffer,
  mac: Uint8Array,
  length: number
): void;

export function verifyMACParts(
  parts: Buffer[],
  key: Buffer,
  mac: Uint8Array,
  length: number
): void;

export function deriveSecrets(
  key: Uint8Array,
  salt: Buffer,
  info: Buffer
): [Buffer, Buffer];

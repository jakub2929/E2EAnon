import { describe, it, expect } from "vitest";
import {
  generateRoomKey,
  encryptMessage,
  decryptMessage,
  keyToString,
  keyFromString,
} from "./crypto";

describe("message crypto (XChaCha20-Poly1305)", () => {
  it("round-trips a message", () => {
    const key = generateRoomKey();
    const env = encryptMessage(key, "hello, world 🌍");
    expect(decryptMessage(key, env)).toBe("hello, world 🌍");
  });

  it("produces ciphertext that does not contain the plaintext", () => {
    const key = generateRoomKey();
    const env = encryptMessage(key, "topsecret");
    expect(env).not.toContain("topsecret");
    // Envelope is opaque base64; decoding it must not reveal the plaintext.
    expect(atob(env)).not.toContain("topsecret");
  });

  it("uses a fresh nonce each time (distinct ciphertexts)", () => {
    const key = generateRoomKey();
    const a = encryptMessage(key, "same message");
    const b = encryptMessage(key, "same message");
    expect(a).not.toBe(b);
  });

  it("fails to decrypt with the wrong key", () => {
    const env = encryptMessage(generateRoomKey(), "secret");
    expect(() => decryptMessage(generateRoomKey(), env)).toThrow();
  });

  it("fails to decrypt tampered ciphertext", () => {
    const key = generateRoomKey();
    const env = encryptMessage(key, "secret");
    // Flip a character in the middle of the base64 envelope.
    const i = Math.floor(env.length / 2);
    const tampered = env.slice(0, i) + (env[i] === "A" ? "B" : "A") + env.slice(i + 1);
    expect(() => decryptMessage(key, tampered)).toThrow();
  });

  it("rejects a truncated envelope", () => {
    const key = generateRoomKey();
    expect(() => decryptMessage(key, "AAAA")).toThrow();
  });
});

describe("room key fragment encoding", () => {
  it("round-trips a key through base64url", () => {
    const key = generateRoomKey();
    const s = keyToString(key);
    expect(s).not.toMatch(/[+/=]/); // url-safe, unpadded
    expect(Array.from(keyFromString(s))).toEqual(Array.from(key));
  });

  it("rejects a wrong-length key string", () => {
    expect(() => keyFromString("AAAA")).toThrow();
  });
});

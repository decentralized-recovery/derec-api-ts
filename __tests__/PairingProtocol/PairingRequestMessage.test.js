/*
 * Copyright (C) 2023 Swirlds Labs Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Filename: PairingRequestMessage.test.js
 * Description: Tests for pairing request message
 */
import { ProtocolType, MessageType, OperatingMode } from "../../src/DeRecTypes";
import { PairingRequestMessage } from "../../src/PairingProtocol/PairingRequestMessage";
import { randomBytes } from "@stablelib/random";
import { KeyPair, generateKeyPairFromSeed, sign, SEED_LENGTH, convertSecretKeyToX25519, convertPublicKeyToX25519 } from "@stablelib/ed25519";
import { AES } from "@stablelib/aes";
import { GCM, NONCE_LENGTH } from "@stablelib/gcm";

var serializedTestMessage = null;
var gcm = null;
var iv = null;

const protocolVersion = 1;
const testUser = {
  counter: 0x12,
  nonce: 0x34,
  operatingMode: OperatingMode.RECOVERY,
  name: "Alice",
  phone: "555 123 4567",
  ecdhPublicKey: new Uint8Array(32).fill(0).map((data, index) => index),
};

beforeAll(() => {
  const seed = randomBytes(SEED_LENGTH);
  const keyPair = generateKeyPairFromSeed(seed);
  const cipher = new AES(keyPair.publicKey);
  gcm = new GCM(cipher);
  iv = randomBytes(NONCE_LENGTH);
});

describe("PairingRequestMessage", () => {
  it("serializes", async () => {
    const pairingRequestMessage = new PairingRequestMessage(protocolVersion, testUser.counter, testUser.nonce, testUser.operatingMode, testUser.name, testUser.phone, testUser.ecdhPublicKey);
    const serialized = pairingRequestMessage.serialize(gcm, iv);
    expect(serialized.length).toBeGreaterThan(20);
    expect(serialized[0]).toEqual(protocolVersion >> 8); // protocol version
    expect(serialized[1]).toEqual(protocolVersion & 0xff);
    serializedTestMessage = serialized;
    let s = "";
    for (let i = 0; i < serialized.length; i++) {
      s += `[${i}: ${serialized[i]}]   `;
    }
    console.log(s);
  });
  it("deserializes", async () => {
    const pairingRequestMessage = new PairingRequestMessage();
    const deserialized = pairingRequestMessage.deserialize(gcm, iv, serializedTestMessage);
    expect(deserialized.getProtocolType()).toEqual(ProtocolType.PAIRING_PROTOCOL);
    expect(deserialized.getMessageType()).toEqual(MessageType.PAIRING_REQUEST);
    expect(deserialized.getCounter()).toEqual(testUser.counter);
    expect(deserialized.getNonce()).toEqual(testUser.nonce);
    expect(deserialized.getOperatingMode()).toEqual(testUser.operatingMode);
    expect(deserialized.getName()).toEqual(testUser.name);
    expect(deserialized.getPhone()).toEqual(testUser.phone);
    expect(deserialized.getEcdhPublicKey()).toEqual(testUser.ecdhPublicKey);
  });
  it("returns correct firstInProtocol()", async () => {
    const pairingRequestMessage = new PairingRequestMessage(protocolVersion, testUser.counter, testUser.nonce, testUser.operatingMode, testUser.name, testUser.phone, testUser.ecdhPublicKey);
    expect(pairingRequestMessage.firstInProtocol()).toEqual(true);
  });

  // it("encrypts and decrypts", async () => {
  //   const PairingRequestMessage = new PairingRequestMessage();
  //   const testData = new Uint8Array(100).fill(0).map((data, index) => index);

  //   const encryptedData = PairingRequestMessage.encrypt(testData, gcm, iv);
  //   const decryptedData = PairingRequestMessage.decrypt(encryptedData, gcm, iv);
  //   expect(decryptedData).toEqual(testData);
  // });

  it("returns correct protocol version", async () => {
    const pairingRequestMessage = new PairingRequestMessage();
    expect(pairingRequestMessage.getProtocolVersion()).toEqual(protocolVersion);
  });
});

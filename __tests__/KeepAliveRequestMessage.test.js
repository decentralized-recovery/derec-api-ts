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
 * Filename: Account.test.js
 * Description: Tests serialization/deserialization of Account objects, and tests adding and removing accounts
 * Author: Dipti Mahamuni
 */
// import { Message } from "../src/Message";
// import { MessageType, ProtocolType } from "../src/DeRecTypes";
import { ProtocolType, MessageType } from "../src/DeRecTypes";
import { KeepAliveRequestMessage } from "../src/KeepAliveProtocol/KeepAliveRequestMessage";
import { randomBytes } from "@stablelib/random";
import { KeyPair, generateKeyPairFromSeed, sign, SEED_LENGTH, convertSecretKeyToX25519, convertPublicKeyToX25519 } from "@stablelib/ed25519";
import { AES } from "@stablelib/aes";
import { GCM, NONCE_LENGTH } from "@stablelib/gcm";

var serializedTestMessage = null;
var gcm = null;
var iv = null;

beforeAll(() => {
  const seed = randomBytes(SEED_LENGTH);
  const keyPair = generateKeyPairFromSeed(seed);
  const cipher = new AES(keyPair.publicKey);
  gcm = new GCM(cipher);
  iv = randomBytes(NONCE_LENGTH);
});

describe("KeepAliveRequestMessage", () => {
  it("serializes", async () => {
    const keepAliveRequestMessage = new KeepAliveRequestMessage();
    const serialized = keepAliveRequestMessage.serialize();
    expect(serialized.length).toEqual(2);
    expect(serialized[0]).toEqual(2);
    expect(serialized[1]).toEqual(0);
    serializedTestMessage = serialized;
  });
  it("deserializes", async () => {
    const keepAliveRequestMessage = new KeepAliveRequestMessage();

    const deserialized = keepAliveRequestMessage.deserialize(serializedTestMessage);
    expect(deserialized.getProtocolType()).toEqual(ProtocolType.KEEP_ALIVE_PROTOCOL);
    expect(deserialized.getMessageType()).toEqual(MessageType.KEEP_ALIVE_REQUEST);
  });
  it("returns correct firstInProtocol()", async () => {
    const keepAliveRequestMessage = new KeepAliveRequestMessage();
    expect(keepAliveRequestMessage.firstInProtocol()).toEqual(true);
  });

  it("encrypts and decrypts", async () => {
    const keepAliveRequestMessage = new KeepAliveRequestMessage();
    const testData = new Uint8Array(100).fill(0).map((data, index) => index);

    const encryptedData = keepAliveRequestMessage.encrypt(testData, gcm, iv);
    const decryptedData = keepAliveRequestMessage.decrypt(encryptedData, gcm, iv);
    expect(decryptedData).toEqual(testData);
  });

  it("returns correct protocol version", async () => {
    const keepAliveRequestMessage = new KeepAliveRequestMessage();
    expect(keepAliveRequestMessage.getProtocolVersion()).toEqual(1);
  });
});

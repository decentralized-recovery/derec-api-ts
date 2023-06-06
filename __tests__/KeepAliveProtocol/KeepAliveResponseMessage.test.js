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
import { ProtocolType, MessageType } from "../../src/DeRecTypes";
import { KeepAliveResponseMessage } from "../../src/KeepAliveProtocol/KeepAliveResponseMessage";
import { randomBytes } from "@stablelib/random";
import { KeyPair, generateKeyPairFromSeed, sign, SEED_LENGTH, convertSecretKeyToX25519, convertPublicKeyToX25519 } from "@stablelib/ed25519";
import { AES } from "@stablelib/aes";
import { GCM, NONCE_LENGTH } from "@stablelib/gcm";

var serializedTestMessage = null;
var gcm = null;
var iv = null;

const protocolVersion = 1;

const testStoredLockboxShareVersion = 0x1234;

beforeAll(() => {
  const seed = randomBytes(SEED_LENGTH);
  const keyPair = generateKeyPairFromSeed(seed);
  const cipher = new AES(keyPair.publicKey);
  gcm = new GCM(cipher);
  iv = randomBytes(NONCE_LENGTH);
});

describe("KeepAliveResponseMessage", () => {
  it("serializes", async () => {
    const keepAliveResponseMessage = new KeepAliveResponseMessage(protocolVersion, testStoredLockboxShareVersion);

    const serialized = keepAliveResponseMessage.serialize(gcm, iv);
    expect(serialized.length).toEqual(6);
    expect(serialized[0]).toEqual(protocolVersion >> 8); // Protocol version
    expect(serialized[1]).toEqual(protocolVersion & 0xff);
    expect(serialized[2]).toEqual(MessageType.KEEP_ALIVE_RESPONSE >> 8);
    expect(serialized[3]).toEqual(MessageType.KEEP_ALIVE_RESPONSE & 0xff);
    expect(serialized[4]).toEqual(testStoredLockboxShareVersion >> 8);
    expect(serialized[5]).toEqual(testStoredLockboxShareVersion & 0xff);
    serializedTestMessage = serialized;
  });
  it("deserializes", async () => {
    const keepAliveResponseMessage = new KeepAliveResponseMessage();
    const deserialized = keepAliveResponseMessage.deserialize(gcm, iv, serializedTestMessage);
    expect(deserialized.getProtocolType()).toEqual(ProtocolType.KEEP_ALIVE_PROTOCOL);
    expect(deserialized.getMessageType()).toEqual(MessageType.KEEP_ALIVE_RESPONSE);
    expect(deserialized.getStoredLockboxShareVersion()).toEqual(testStoredLockboxShareVersion);
  });

  it("returns correct firstInProtocol()", async () => {
    const keepAliveResponseMessage = new KeepAliveResponseMessage();
    expect(keepAliveResponseMessage.firstInProtocol()).toEqual(false);
  });

  it("returns correct protocol version", async () => {
    const keepAliveResponseMessage = new KeepAliveResponseMessage();
    expect(keepAliveResponseMessage.getProtocolVersion()).toEqual(protocolVersion);
  });
});

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
 * Filename: PairingAckMessage.test.js
 * Description: Tests for pairing response message
 */
import { ProtocolType, MessageType, OperatingMode } from "../../src/DeRecTypes";
import { PairingAckMessage } from "../../src/PairingProtocol/PairingAckMessage";
import { randomBytes } from "@stablelib/random";
import { KeyPair, generateKeyPairFromSeed, sign, SEED_LENGTH, convertSecretKeyToX25519, convertPublicKeyToX25519 } from "@stablelib/ed25519";
import { AES } from "@stablelib/aes";
import { GCM, NONCE_LENGTH } from "@stablelib/gcm";

var serializedTestMessage = null;
var gcm = null;
var iv = null;

const protocolVersion = 1;

beforeAll(() => {
  const seed = randomBytes(SEED_LENGTH);
  const keyPair = generateKeyPairFromSeed(seed);
  const cipher = new AES(keyPair.publicKey);
  gcm = new GCM(cipher);
  iv = randomBytes(NONCE_LENGTH);
});

describe("PairingAckMessage", () => {
  it("serializes", async () => {
    const pairingAckMessage = new PairingAckMessage(protocolVersion);
    const serialized = pairingAckMessage.serialize(gcm, iv);
    expect(serialized.length).toBeGreaterThan(2);
    expect(serialized[0]).toEqual(protocolVersion >> 8); // protocol version
    expect(serialized[1]).toEqual(protocolVersion & 0xff);
    serializedTestMessage = serialized;
  });
  it("deserializes", async () => {
    const pairingAckMessage = new PairingAckMessage();
    const deserialized = pairingAckMessage.deserialize(gcm, iv, serializedTestMessage);
    expect(deserialized.getProtocolType()).toEqual(ProtocolType.PAIRING_PROTOCOL);
    expect(deserialized.getMessageType()).toEqual(MessageType.PAIRING_ACK);
  });
  it("returns correct firstInProtocol()", async () => {
    const pairingAckMessage = new PairingAckMessage(protocolVersion);
    expect(pairingAckMessage.firstInProtocol()).toEqual(false);
  });

  it("returns correct protocol version", async () => {
    const pairingAckMessage = new PairingAckMessage();
    expect(pairingAckMessage.getProtocolVersion()).toEqual(protocolVersion);
  });
});

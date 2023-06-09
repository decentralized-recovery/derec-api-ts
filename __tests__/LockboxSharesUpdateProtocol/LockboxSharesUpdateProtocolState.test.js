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

import { ProtocolType, MessageType } from "../../src/DeRecTypes";
import { KeepAliveRequestMessage } from "../../src/KeepAliveProtocol/KeepAliveRequestMessage";
import { KeepAliveResponseMessage } from "../../src/KeepAliveProtocol/KeepAliveResponseMessage";
import { KeepAliveProtocolState } from "../../src/KeepAliveProtocol/KeepAliveProtocolState";
import { LockboxSharesUpdateProtocolState } from "../../src/LockboxSharesUpdateProtocol/LockboxSharesUpdateProtocolState";
import { randomBytes } from "@stablelib/random";
import { KeyPair, generateKeyPairFromSeed, sign, SEED_LENGTH, convertSecretKeyToX25519, convertPublicKeyToX25519 } from "@stablelib/ed25519";
import { AES } from "@stablelib/aes";
import { GCM, NONCE_LENGTH } from "@stablelib/gcm";
import { ProtocolState } from "../../src/ProtocolState";

var protocol = null;

beforeAll(() => {});

describe("LockboxSharesUpdateProtocolState", () => {
  it("starts a new lockbox shares protocol", async () => {
    protocol = new LockboxSharesUpdateProtocolState();
    expect(protocol).not.toBeNull();
  });
});

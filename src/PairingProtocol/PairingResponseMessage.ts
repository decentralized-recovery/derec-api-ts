import { AES } from "@stablelib/aes";
import { GCM, NONCE_LENGTH } from "@stablelib/gcm";
import { Message } from "../Message";
import { MessageType, ProtocolType, OperatingMode } from "../DeRecTypes";

export class PairingResponseMessage extends Message {
  private readonly messageType: MessageType = MessageType.PAIRING_RESPONSE;
  private readonly protocolType: ProtocolType = ProtocolType.PAIRING_PROTOCOL;

  private readonly _firstCounter: number;
  private readonly _nonces: Array<number>;
  private readonly _operatingMode: OperatingMode;
  private readonly _name: string; // in the RFC this is two fields: the name and the length of the name
  private readonly _phone: string; // in the RFC this is two fields: the name and the length of the name
  private readonly _ecdhPublicKey: Uint8Array;

  /* constructor, with parameters for all fields except MessageType */
  // Multiple constructors in typescript style
  constructor(protocolVersion: number, firstCounter: number, nonces: Array<number>, operatingMode: OperatingMode, name: string, phone: string, ecdhPublicKey: Uint8Array);
  constructor();
  constructor(...constructorArgsArr: any[]) {
    super();
    if (constructorArgsArr.length === 0) {
      return;
    } else {
      let index = 0;
      this._protocolVersion = constructorArgsArr[index++];
      this._firstCounter = constructorArgsArr[index++];
      this._nonces = constructorArgsArr[index++];
      this._operatingMode = constructorArgsArr[index++];
      this._name = constructorArgsArr[index++];
      this._phone = constructorArgsArr[index++];
      this._ecdhPublicKey = constructorArgsArr[index++];
    }
  }

  serialize(hseAesGcm: GCM, iv: Uint8Array): Uint8Array {
    if (this._protocolVersion == 1) {
      const protocolVersion = new Uint8Array(2);
      protocolVersion.set([this._protocolVersion >> 8, this._protocolVersion & 0xff], 0);

      const messageType = new Uint8Array(2);
      messageType.set([MessageType.PAIRING_RESPONSE >> 8, MessageType.PAIRING_RESPONSE & 0xff], 0);

      const ecdhPublicKeyLen = new Uint8Array(2);
      ecdhPublicKeyLen.set([this._ecdhPublicKey.length >> 8, this._ecdhPublicKey.length & 0xff], 0);
      const ecdhPublicKeyArr = new Uint8Array(Buffer.from(this._ecdhPublicKey));

      const sectionToEncrypt = this.serializeEncryptedSection();
      const encryptedSection = super.encrypt(hseAesGcm, iv, sectionToEncrypt);

      const serialized: Uint8Array = new Uint8Array([...protocolVersion, ...messageType, ...ecdhPublicKeyLen, ...ecdhPublicKeyArr, ...encryptedSection]);
      return serialized;
    } else {
      throw `Unknown protocol version number ${this._protocolVersion} in PairingResponseMessage::serialize`;
    }
  }

  serializeEncryptedSection(): Uint8Array {
    if (this._protocolVersion == 1) {
      const counter = new Uint8Array(1);
      counter.set([this._firstCounter], 0);

      const noncesLen = new Uint8Array(2);
      noncesLen.set([this._nonces.length >> 8, this._nonces.length & 0xff], 0);
      const noncesArr = new Uint8Array(Buffer.from(this._nonces));

      const operatingMode = new Uint8Array(1);
      operatingMode.set([this._operatingMode], 0);

      const nameLen = new Uint8Array(2);
      nameLen.set([this._name.length >> 8, this._name.length & 0xff], 0);
      const nameArr = new Uint8Array(Buffer.from(this._name));

      const phoneLen = new Uint8Array(2);
      phoneLen.set([this._phone.length >> 8, this._phone.length & 0xff], 0);
      const phoneArr = new Uint8Array(Buffer.from(this._phone));

      const serialized: Uint8Array = new Uint8Array([...counter, ...noncesLen, ...noncesArr, ...operatingMode, ...nameLen, ...nameArr, ...phoneLen, ...phoneArr]);
      return serialized;
    } else {
      throw `Unknown protocol version number ${this._protocolVersion} in PairingResponseMessage::serializeEncryptedSection`;
    }
  }

  /**
      @return a new object instantiated with the data from this message,
      parsed according to the format defined by the RFC
      */
  deserialize(hseAesGcm: GCM, iv: Uint8Array, message: Uint8Array): Message {
    const serialized = new Uint8Array(message);

    let index = 0;
    const protocolVersionDataView = new DataView(serialized.buffer, index, 2);
    const protocolVersion = protocolVersionDataView.getUint16(0, false);
    index += 2;

    if (protocolVersion == 1) {
      const messageTypeDataView = new DataView(serialized.buffer, index, 2);
      const messageType = messageTypeDataView.getUint16(0, false);
      index += 2;

      if (messageType != MessageType.PAIRING_RESPONSE) {
        throw `PairingResponseMessage tried to deserialized message type: ${messageType}`;
      }

      const ecdhPublicKeyLenDataView = new DataView(serialized.buffer, index, 2);
      const ecdhPublicKeyLen = ecdhPublicKeyLenDataView.getUint16(0, false);
      index += 2;

      const ecdhPublicKey = new Uint8Array(serialized.slice(index, index + ecdhPublicKeyLen));
      index += ecdhPublicKeyLen;

      const encryptedSection = new Uint8Array(serialized.slice(index));

      const deserializedDecryptedSection = super.decrypt(hseAesGcm, iv, encryptedSection);
      const decrypted = this.deserializeEncryptedSection(deserializedDecryptedSection);

      return new PairingResponseMessage(protocolVersion, decrypted.firstCounter, decrypted.nonces, decrypted.operatingMode, decrypted.name, decrypted.phone, ecdhPublicKey);
    } else {
      throw `Unknown protocol version number ${protocolVersion} in PairingResponseMessage::deserialize`;
    }
  }

  deserializeEncryptedSection(serialized: Uint8Array): any {
    let index = 0;
    let ret: any = {};

    const firstCounterDataView = new DataView(serialized.buffer, index, 1);
    ret.firstCounter = firstCounterDataView.getUint8(0);
    index += 1;

    const noncesLenDataView = new DataView(serialized.buffer, index, 2);
    const noncesLen = noncesLenDataView.getUint16(0, false);
    index += 2;

    ret.nonces = new Uint8Array(serialized.slice(index, index + noncesLen));
    index += noncesLen;

    const operatingModeDataView = new DataView(serialized.buffer, index, 1);
    ret.operatingMode = operatingModeDataView.getUint8(0);
    index += 1;

    const nameLenDataView = new DataView(serialized.buffer, index, 2);
    const nameLen = nameLenDataView.getUint16(0, false);
    index += 2;

    ret.name = Buffer.from(serialized.buffer.slice(index, index + nameLen)).toString("utf-8");
    index += nameLen;

    const phoneLenDataView = new DataView(serialized.buffer, index, 2);
    const phoneLen = phoneLenDataView.getUint16(0, false);
    index += 2;

    ret.phone = Buffer.from(serialized.buffer.slice(index, index + phoneLen)).toString("utf-8");
    index += phoneLen;

    return ret;
  }

  /* getters for all the fields */

  getProtocolType(): ProtocolType {
    return this.protocolType;
  }
  /**
      @return the type of message
      */
  getMessageType(): MessageType {
    return this.messageType;
  }

  getFirstCounter(): number {
    return this._firstCounter;
  }
  getNonces(): Array<number> {
    return this._nonces;
  }
  getOperatingMode(): OperatingMode {
    return this._operatingMode;
  }
  getName(): string {
    return this._name;
  }
  getPhone(): string {
    return this._phone;
  }
  getEcdhPublicKey(): Uint8Array {
    return this._ecdhPublicKey;
  }

  /**
      @return true if this message is the first message starting a new protocol conversation
      */
  firstInProtocol(): boolean {
    return false;
  }
}

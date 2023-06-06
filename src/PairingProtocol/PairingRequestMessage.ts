import { AES } from "@stablelib/aes";
import { GCM, NONCE_LENGTH } from "@stablelib/gcm";
import { Message } from "../Message";
import { MessageType, ProtocolType, OperatingMode } from "../DeRecTypes";

export class PairingRequestMessage extends Message {
  private readonly messageType: MessageType = MessageType.PAIRING_REQUEST;
  private readonly protocolType: ProtocolType = ProtocolType.PAIRING_PROTOCOL;

  private readonly _counter: number;
  private readonly _nonce: number;
  private readonly _operatingMode: OperatingMode;
  private readonly _name: string; // in the RFC this is two fields: the name and the length of the name
  private readonly _phone: string; // in the RFC this is two fields: the name and the length of the name
  private readonly _ecdhPublicKey: Uint8Array;

  /* constructor, with parameters for all fields except MessageType */
  // Multiple constructors in typescript style
  constructor(protocolVersion: number, counter: number, nonce: number, operatingMode: OperatingMode, name: string, phone: string, ecdhPublicKey: Uint8Array);
  constructor();
  constructor(...constructorArgsArr: any[]) {
    super();
    if (constructorArgsArr.length === 0) {
      return;
    } else {
      let index = 0;
      this._protocolVersion = constructorArgsArr[index++];
      this._counter = constructorArgsArr[index++];
      this._nonce = constructorArgsArr[index++];
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
      messageType.set([MessageType.PAIRING_REQUEST >> 8, MessageType.PAIRING_REQUEST & 0xff], 0);

      const counter = new Uint8Array(1);
      counter.set([this._counter], 0);

      const nonce = new Uint8Array(1);
      nonce.set([this._nonce], 0);

      const operatingMode = new Uint8Array(1);
      operatingMode.set([this._operatingMode], 0);

      const nameLen = new Uint8Array(2);
      nameLen.set([this._name.length >> 8, this._name.length & 0xff], 0);
      const nameArr = new Uint8Array(Buffer.from(this._name));

      const phoneLen = new Uint8Array(2);
      phoneLen.set([this._phone.length >> 8, this._phone.length & 0xff], 0);
      const phoneArr = new Uint8Array(Buffer.from(this._phone));

      const ecdhPublicKeyLen = new Uint8Array(2);
      ecdhPublicKeyLen.set([this._ecdhPublicKey.length >> 8, this._ecdhPublicKey.length & 0xff], 0);
      const ecdhPublicKeyArr = new Uint8Array(Buffer.from(this._ecdhPublicKey));

      const serialized: Uint8Array = new Uint8Array([...protocolVersion, ...messageType, ...counter, ...nonce, ...operatingMode, ...nameLen, ...nameArr, ...phoneLen, ...phoneArr, ...ecdhPublicKeyLen, ...ecdhPublicKeyArr]);
      return serialized;
    } else {
      throw `Unknown protocol version number ${this._protocolVersion} in PairingRequestMessage::serialize`;
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

      if (messageType != MessageType.PAIRING_REQUEST) {
        throw `PairingRequestMessage tried to deserialized message type: ${messageType}`;
      }

      const counterDataView = new DataView(serialized.buffer, index, 1);
      const counter = counterDataView.getUint8(0);
      index += 1;

      const nonceDataView = new DataView(serialized.buffer, index, 1);
      const nonce = nonceDataView.getUint8(0);
      index += 1;

      const operatingModeDataView = new DataView(serialized.buffer, index, 1);
      const operatingMode = operatingModeDataView.getUint8(0);
      index += 1;

      const nameLenDataView = new DataView(serialized.buffer, index, 2);
      const nameLen = nameLenDataView.getUint16(0, false);
      index += 2;

      const name = Buffer.from(serialized.buffer.slice(index, index + nameLen)).toString("utf-8");
      index += nameLen;

      const phoneLenDataView = new DataView(serialized.buffer, index, 2);
      const phoneLen = phoneLenDataView.getUint16(0, false);
      index += 2;

      const phone = Buffer.from(serialized.buffer.slice(index, index + phoneLen)).toString("utf-8");
      index += phoneLen;

      const ecdhPublicKeyLenDataView = new DataView(serialized.buffer, index, 2);
      const ecdhPublicKeyLen = ecdhPublicKeyLenDataView.getUint16(0, false);
      index += 2;

      const ecdhPublicKey = new Uint8Array(serialized.buffer.slice(index, index + ecdhPublicKeyLen));
      index += ecdhPublicKeyLen;

      return new PairingRequestMessage(protocolVersion, counter, nonce, operatingMode, name, phone, ecdhPublicKey);
    } else {
      throw `Unknown protocol version number ${protocolVersion} in PairingRequestMessage::deserialize`;
    }
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

  getCounter(): number {
    return this._counter;
  }
  getNonce(): number {
    return this._nonce;
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
    return true;
  }
}

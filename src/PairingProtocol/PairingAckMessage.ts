import { AES } from "@stablelib/aes";
import { GCM, NONCE_LENGTH } from "@stablelib/gcm";
import { Message } from "../Message";
import { MessageType, ProtocolType, OperatingMode } from "../DeRecTypes";

export class PairingAckMessage extends Message {
  private readonly messageType: MessageType = MessageType.PAIRING_ACK;
  private readonly protocolType: ProtocolType = ProtocolType.PAIRING_PROTOCOL;

  /* constructor, with parameters for all fields except MessageType */
  // Multiple constructors in typescript style
  constructor(protocolVersion: number);
  constructor();
  constructor(...constructorArgsArr: any[]) {
    super();
    if (constructorArgsArr.length === 0) {
      return;
    } else {
      this._protocolVersion = constructorArgsArr[0];
    }
  }

  serialize(hseAesGcm: GCM, iv: Uint8Array): Uint8Array {
    if (this._protocolVersion == 1) {
      const protocolVersion = new Uint8Array(2);
      protocolVersion.set([this._protocolVersion >> 8, this._protocolVersion & 0xff], 0);

      const sectionToEncrypt = this.serializeEncryptedSection();
      const encryptedSection = super.encrypt(hseAesGcm, iv, sectionToEncrypt);

      const serialized: Uint8Array = new Uint8Array([...protocolVersion, ...encryptedSection]);
      return serialized;
    } else {
      throw `Unknown protocol version number ${this._protocolVersion} in PairingAckMessage::serialize`;
    }
  }

  serializeEncryptedSection(): Uint8Array {
    if (this._protocolVersion == 1) {
      const messageType = new Uint8Array(2);
      messageType.set([MessageType.PAIRING_ACK >> 8, MessageType.PAIRING_ACK & 0xff], 0);

      const serialized: Uint8Array = new Uint8Array([...messageType]);
      return serialized;
    } else {
      throw `Unknown protocol version number ${this._protocolVersion} in PairingAckMessage::serializeEncryptedSection`;
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
      const encryptedSection = new Uint8Array(serialized.slice(index));

      const deserializedDecryptedSection = super.decrypt(hseAesGcm, iv, encryptedSection);
      const decrypted = this.deserializeEncryptedSection(deserializedDecryptedSection);
      if (decrypted.messageType != MessageType.PAIRING_ACK) {
        throw `PairingAckMessage tried to deserialized message type: ${decrypted.messageType}`;
      }

      return new PairingAckMessage(protocolVersion);
    } else {
      throw `Unknown protocol version number ${protocolVersion} in PairingAckMessage::deserialize`;
    }
  }

  deserializeEncryptedSection(serialized: Uint8Array): any {
    let index = 0;
    let ret: any = {};

    const messageTypeDataView = new DataView(serialized.buffer, index, 2);
    ret.messageType = messageTypeDataView.getUint16(0, false);
    index += 2;

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

  /**
      @return true if this message is the first message starting a new protocol conversation
      */
  firstInProtocol(): boolean {
    return false;
  }
}

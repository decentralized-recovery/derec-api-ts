import { AES } from "@stablelib/aes";
import { GCM, NONCE_LENGTH } from "@stablelib/gcm";
import { Message } from "../Message";
import { MessageType, ProtocolType } from "../DeRecTypes";

export class KeepAliveResponseMessage extends Message {
  private messageType: MessageType = MessageType.KEEP_ALIVE_RESPONSE;
  private protocolType: ProtocolType = ProtocolType.KEEP_ALIVE_PROTOCOL;
  private readonly _storedLockboxShareVersion: number;

  /* constructor, with parameters for all fields except MessageType */
  // Multiple constructors in typescript style
  constructor(protocolVersion: number, storedLockboxShareVersion: number);
  constructor();
  constructor(...constructorArgsArr: any[]) {
    super();
    if (constructorArgsArr.length === 0) {
      return;
    } else {
      let index = 0;
      this._protocolVersion = constructorArgsArr[index++];
      this._storedLockboxShareVersion = constructorArgsArr[index++];
    }
  }

  serialize(hseAesGcm: GCM, iv: Uint8Array): Uint8Array {
    if (this._protocolVersion == 1) {
      const protocolVersion = new Uint8Array(2);
      protocolVersion.set([this._protocolVersion >> 8, this._protocolVersion & 0xff], 0);

      const messageType = new Uint8Array(2);
      messageType.set([MessageType.KEEP_ALIVE_RESPONSE >> 8, MessageType.KEEP_ALIVE_RESPONSE & 0xff], 0);

      const storedLockboxShareVersionArr = new Uint8Array(2);
      storedLockboxShareVersionArr.set([this._storedLockboxShareVersion >> 8, this._storedLockboxShareVersion & 0xff], 0);

      const serialized: Uint8Array = new Uint8Array([...protocolVersion, ...messageType, ...storedLockboxShareVersionArr]);
      return serialized;
    } else {
      throw `Unknown protocol version number ${this._protocolVersion} in KeepAliveResponseMessage::serialize`;
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

      if (messageType != MessageType.KEEP_ALIVE_RESPONSE) {
        throw `KeepAliveResponseMessage tried to deserialized message type: ${messageType}`;
      }
      const storedLockboxShareVersionArrDataView = new DataView(serialized.buffer, index, 2);
      const deserializedStoredLockboxShareVersion = (storedLockboxShareVersionArrDataView.getUint8(0) << 8) + storedLockboxShareVersionArrDataView.getUint8(1);
      index += 2;

      return new KeepAliveResponseMessage(protocolVersion, deserializedStoredLockboxShareVersion);
    } else {
      throw `Unknown protocol version number ${protocolVersion} in KeepaliveRequestMessage::deserialize`;
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

  getStoredLockboxShareVersion(): number {
    return this._storedLockboxShareVersion;
  }
  /**
      @return true if this message is the first message starting a new protocol conversation
      */
  firstInProtocol(): boolean {
    return false;
  }
}

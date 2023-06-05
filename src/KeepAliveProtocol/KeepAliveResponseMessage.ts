import { Message } from "../Message";
import { MessageType, ProtocolType } from "../DeRecTypes";

export class KeepAliveResponseMessage extends Message {
  private messageType: MessageType = MessageType.KEEP_ALIVE_RESPONSE;
  private protocolType: ProtocolType = ProtocolType.KEEP_ALIVE_PROTOCOL;
  private storedLockboxShareVersion: number;

  /* constructor, with parameters for all fields except MessageType */
  constructor(storedLockboxShareVersion: number) {
    super();
    this.storedLockboxShareVersion = storedLockboxShareVersion;
  }

  serialize(): Uint8Array {
    const messageType = new Uint8Array(2);
    messageType.set([MessageType.KEEP_ALIVE_RESPONSE >> 8, MessageType.KEEP_ALIVE_RESPONSE & 0xff], 0);

    const storedLockboxShareVersionArr = new Uint8Array(2);
    storedLockboxShareVersionArr.set([this.storedLockboxShareVersion >> 8, this.storedLockboxShareVersion & 0xff], 0);

    const serialized: Uint8Array = new Uint8Array([...messageType, ...storedLockboxShareVersionArr]);
    return serialized;
  }

  /**
      @return a new object instantiated with the data from this message,
      parsed according to the format defined by the RFC
      */
  deserialize(message: Uint8Array): Message {
    const serialized = new Uint8Array(message);
    let deserializedStoredLockboxShareVersion = -1;
    if (this.protocolVersion == 1) {
      let index = 0;
      const messageTypeDataView = new DataView(serialized.buffer, index, 2);
      const deserializedMessageType = (messageTypeDataView.getUint8(0) << 8) + messageTypeDataView.getUint8(1);
      index += 2;
      const storedLockboxShareVersionArrDataView = new DataView(serialized.buffer, index, 2);
      const deserializedStoredLockboxShareVersion = (storedLockboxShareVersionArrDataView.getUint8(0) << 8) + storedLockboxShareVersionArrDataView.getUint8(1);
      index += 2;
      if (deserializedMessageType != MessageType.KEEP_ALIVE_RESPONSE) {
        throw `KeepAliveResponseMessage tried to deserialize message type: ${deserializedMessageType}`;
      }
      if (deserializedStoredLockboxShareVersion < 0) {
        throw `Incorrect deserialized stored lockbox share version, recd ${deserializedStoredLockboxShareVersion}`;
      }
    } else {
      throw `KeepAliveResponseMessage tried to deserialize message with protocol version: ${this.protocolVersion}`;
    }

    return new KeepAliveResponseMessage(deserializedStoredLockboxShareVersion);
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

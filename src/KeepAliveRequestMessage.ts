import { Message } from "./Message";
import { MessageType, ProtocolType } from "./DeRecTypes";

export class KeepAliveRequestMessage extends Message {
  private messageType: MessageType = MessageType.KEEP_ALIVE_REQUEST;
  private protocolType: ProtocolType = ProtocolType.KEEP_ALIVE_PROTOCOL;

  /* constructor, with parameters for all fields except MessageType */
  KeepAliveRequestMessage() {}

  serialize(): Uint8Array {
    const messageType = new Uint8Array(2);
    messageType.set([MessageType.KEEP_ALIVE_REQUEST >> 8, MessageType.KEEP_ALIVE_REQUEST & 0xff], 0);
    const serialized: Uint8Array = new Uint8Array([...messageType]);
    return serialized;
  }

  /**
      @return a new object instantiated with the data from this message,
      parsed according to the format defined by the RFC
      */
  deserialize(message: Uint8Array): Message {
    const serialized = new Uint8Array(message);
    if (this.protocolVersion == 1) {
      let index = 0;
      const messageTypeDataView = new DataView(serialized.buffer, index, 2);
      const deserializedMessageType = (messageTypeDataView.getUint8(0) << 8) + messageTypeDataView.getUint8(1);
      index += 2;
      if (deserializedMessageType != MessageType.KEEP_ALIVE_REQUEST) {
        throw `KeepAliveRequestMessage tried to deserialized message type: ${deserializedMessageType}`;
      }
    } else {
      throw `KeepAliveRequestMessage tried to deserialize message with protocol version: ${this.protocolVersion}`;
    }

    return new KeepAliveRequestMessage();
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

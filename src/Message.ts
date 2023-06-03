import { AES } from "@stablelib/aes";
import { GCM, NONCE_LENGTH } from "@stablelib/gcm";
import { MessageType, ProtocolType } from "./DeRecTypes";

/*Each message inherits from this class. Each protocol works by repeatedly sending and receiving messages. Each
   message is sent as a byte array that comes from serializing this message, and each received message is
   instantiated by deserializing a received byte array.
   */
export abstract class Message {
  protocolVersion: number = 1;
  /**
      Serialize to a byte array, suitable for sending as a message.
      For any field that is a string, it is first converted to bytes as UTF-8 with NFC normalization, then
      serialized as a Uint16 length followed by the bytes.
      @return create a message from this object, serialized in the format defined by the RFC
      */
  abstract serialize(): Uint8Array;

  /**
      @return a new object instantiated with the data from this message,
      parsed according to the format defined by the RFC
      */
  abstract deserialize(message: Uint8Array): Message;

  encrypt(serializedMessage: Uint8Array, hseAesGcm: GCM, iv: Uint8Array): Uint8Array {
    const sealed = hseAesGcm.seal(iv, serializedMessage);
    return sealed;
  }

  decrypt(encryptedMessage: Uint8Array, hseAesGcm: GCM, iv: Uint8Array): Uint8Array {
    const unsealed = hseAesGcm.open(iv, encryptedMessage);
    return unsealed ? unsealed : new Uint8Array(0);
  }

  getProtocolVersion(): number {
    return this.protocolVersion;
  }

  /**
      @return the type of message
      */
  abstract getMessageType(): MessageType;

  /**
      @return the protocol that uses this message type
      */
  abstract getProtocolType(): ProtocolType;

  /**
      @return true if this message is the first message starting a new protocol conversation
      */
  abstract firstInProtocol(): boolean;
}

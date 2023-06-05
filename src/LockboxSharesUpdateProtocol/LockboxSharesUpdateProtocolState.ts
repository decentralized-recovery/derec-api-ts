import { MessageType, ProtocolStatus, ProtocolType } from "../DeRecTypes";
import { Message } from "../Message";
import { ProtocolState } from "../ProtocolState";

export enum StatesForLokcboxUpdatesProtocol {
  OUT_OF_SYNC,
  IN_SYNC,
  FASTER_KEEP_ALIVES,
}

export class LockboxSharesUpdateProtocolState extends ProtocolState {
  private _state: StatesForLokcboxUpdatesProtocol = StatesForLokcboxUpdatesProtocol.OUT_OF_SYNC;
  private _timer: any = null;
  private static _receivedLockboxShareVersion: Map<string, number>;

  constructor() {
    super();
    console.log(`in constructor for LockboxSharesUpdateProtocolState `);
    this._protocolStatus = ProtocolStatus.NOT_STARTED;
    LockboxSharesUpdateProtocolState._receivedLockboxShareVersion = new Map();
  }
  public processMessage(message: Message): boolean {
    if (message.getProtocolType() !== ProtocolType.LOCKBOX_SHARES_UPDATE_PROTOCOL) {
      return false;
    }
    switch (message.getMessageType()) {
      case MessageType.STORE_LOCKBOX_SHARE_REQUEST:
        const version = 23; // TODO: Get it from the received message
        LockboxSharesUpdateProtocolState._receivedLockboxShareVersion.set("4081111111", version);
        break;
      case MessageType.KEEP_ALIVE_RESPONSE:
        break;
      default:
        throw `KeepaliveProtocolState encounterd unknown message type: ${message.getMessageType()}`;
        break;
    }
    return true;
  }
  public static getLockboxShareVersion(phone: string): number | undefined {
    return LockboxSharesUpdateProtocolState._receivedLockboxShareVersion.get(phone);
  }
}

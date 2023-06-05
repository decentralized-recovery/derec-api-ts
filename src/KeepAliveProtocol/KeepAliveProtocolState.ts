import { MessageType, ProtocolStatus, ProtocolType } from "../DeRecTypes";
import { Message } from "../Message";
import { ProtocolState } from "../ProtocolState";
import { KeepAliveRequestMessage } from "./KeepAliveRequestMessage";
import { KeepAliveResponseMessage } from "./KeepAliveResponseMessage";
// import { LockboxSharesUpdateProtocolState } from "../LockboxSharesUpdateProtocol/LockboxSharesUpdateProtocolState";

export enum StatesForKeepAliveProtocol {
  OUT_OF_SYNC = "Out of Sync",
  IN_SYNC = "In Sync",
  FASTER_KEEP_ALIVES = "Faster Keepalives",
}

export const KEEP_ALIVE_TIMER_NORMAL: number = 10000; // 1 second
export const KEEP_ALIVE_TIMER_FAST: number = 5000; // 1/2 second

export const MAX_UNRESPONDED_REQUESTS_NORMAL: number = 5;
export const MAX_UNRESPONDED_REQUESTS_FAST: number = MAX_UNRESPONDED_REQUESTS_NORMAL + 10;

export class KeepAliveProtocolState extends ProtocolState {
  private _state: StatesForKeepAliveProtocol = StatesForKeepAliveProtocol.OUT_OF_SYNC;
  private _timer: any = null;
  private _unrespondedRequests: number;

  constructor() {
    super();
    this._protocolStatus = ProtocolStatus.NOT_STARTED;
    this._timer = setInterval(() => this._timerTask(), KEEP_ALIVE_TIMER_NORMAL);
    this._unrespondedRequests = 0;
  }

  _timerTask() {
    // console.log(`in timerTask for keepalive protocol - queing up keepalive request message. _unrespondedRequests: ${this._unrespondedRequests}`);

    const keepaliveRequest = new KeepAliveRequestMessage();
    this._nextMessageToSend.push(keepaliveRequest);
    this._unrespondedRequests++;

    if (this._unrespondedRequests > MAX_UNRESPONDED_REQUESTS_FAST) {
      this._state = StatesForKeepAliveProtocol.OUT_OF_SYNC;
    } else if (this._unrespondedRequests > MAX_UNRESPONDED_REQUESTS_NORMAL) {
      this._state = StatesForKeepAliveProtocol.FASTER_KEEP_ALIVES;
    }
  }

  public stopPeriodicTimer() {
    clearInterval(this._timer);
  }

  public processMessage(message: Message): boolean {
    if (message.getProtocolType() !== ProtocolType.KEEP_ALIVE_PROTOCOL) {
      return false;
    }

    switch (message.getMessageType()) {
      case MessageType.KEEP_ALIVE_REQUEST:
        // const peerLockboxShareVersion = LockboxSharesUpdateProtocolState.getLockboxShareVersion("4081111111");
        const peerLockboxShareVersion = 34;
        if (peerLockboxShareVersion) {
          const response = new KeepAliveResponseMessage(peerLockboxShareVersion);
          this._nextMessageToSend.push(response);
        }
        break;
      case MessageType.KEEP_ALIVE_RESPONSE:
        this._state = StatesForKeepAliveProtocol.IN_SYNC;
        this._unrespondedRequests = 0;
        break;
      default:
        throw `KeepaliveProtocolState encounterd unknown message type: ${message.getMessageType()}`;
        break;
    }
    return true;
  }

  public getProtocolState(): string {
    return this._state;
  }
}

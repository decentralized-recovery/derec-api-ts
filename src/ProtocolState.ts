import { ProtocolStatus, ProtocolType } from "./DeRecTypes";
import { Message } from "./Message";
import { KeepAliveProtocolState } from "./KeepAliveProtocol/KeepAliveProtocolState";
import { LockboxSharesUpdateProtocolState } from "./LockboxSharesUpdateProtocol/LockboxSharesUpdateProtocolState";

/** While a protocol conversation is in progress, all needed info is kept in this state. The state for each protocol
 * type should be implemented as a different class that inherits from this one.
 *
 * It is possible for multiple protocols to be happening simultaneously. For example, Alice might be
 * simultaneously engaging in one of these protocols with Bob, while also engaging in a different protocol with
 * Carol. In that case, Alice will instantiate two ProtocolState objects, one for each conversation, feeding each
 * one the next message received from Bob or Carol, and sending to Bob or Carol the messageToSend() that it
 * generates.
 *
 * When Alice receives a message from Bob, she should call ProtocolState.startNew(message). If this message was
 * from Bob trying to start a new protocol conversation, then the factory method will return a new ProtocolState
 * for that conversation. Otherwise, it will return null.  If it returns null, then she can call the
 * processMessage(message) method on all of the existing ProtocolState objects in memory, until she finds one that
 * returns true, indicating that this message was actually an expected next message in that protocol.  If all of
 * them return false, then this was an unexpected message, and it can be discarded.
 *
 * If the message is successfully processed, either by ProtocolState.startNew(message) returning a new object, or
 * by processMessage(message) returning true, then Alice can call messageToSend() on that state object to retrieve
 * the next message to send Bob. And she can call serialize() on that message, to get the actual byte array to send.
 *
 * Each protocol will implement a state that extends ProtocolState, and which will include getters and setters
 * specific to that protocol. For example, when Alice initiates a protocol conversation with Bob, she will first
 * call startProtocol(protocolType) to get a new state for a new conversation. Depending on the protocol, she then
 * might call several setters on the resulting state, then call nextMessageToSend() and send it.
 *
 */
export abstract class ProtocolState {
  /** the current status of this protocol (whether it is started, in progress, failed, etc) */
  protected _protocolStatus: ProtocolStatus = ProtocolStatus.NOT_STARTED;

  /** the next message to send (or null if none). */
  protected _nextMessageToSend: Array<Message> = [];

  /** do not call constructors to instantiate this class. Only use the two static factory methods. */
  constructor() {}

  /** If Alice is starting a new protocol conversation with Bob, she should call startProtocol. Then, the first
   * message to send Bob will either be immediately available from messageToSend(), or she may have to call some
   * methods on the state to provide needed data first, depending on which protocol it is.
   *
   * @param protocolType which protocol to start
   * @return a new state for this new protocol conversation that is starting.
   */
  public static startProtocol(protocolType: ProtocolType): ProtocolState {
    switch (protocolType) {
      case ProtocolType.KEEP_ALIVE_PROTOCOL:
        return new KeepAliveProtocolState();
        break;
      // case ProtocolType.LOCKBOX_SHARES_UPDATE_PROTOCOL:
      //   return new LockboxSharesUpdateProtocolState();
      //   break;
      default:
        throw `ProtocolState::startProtocol encountered an unknown protocol type ${protocolType}`;
    }
  }

  /**
   * If Alice receives a message from Bob, it is possible that this message is a request from him to start a new
   * protocol conversation.  Alice should call this factory method with the message. If message is starting a
   * new conversation, then this returns a new state for that conversation. Otherwise, it returns null.
   *
   * @return the new state for the new protocol conversation started by this message, or null if none
   */
  public static possibleStartProtocol(message: Message): ProtocolState | null {
    if (message.firstInProtocol()) {
      return ProtocolState.startProtocol(message.getProtocolType());
    } else {
      return null;
    }
  }

  /** The next message to send, or null if there is none. Calling this removes the message, so an immediate
   * second call will always return null.
   *
   * @return the message to send next, or undefined if there is none
   */
  public nextMessageToSend(): Message | undefined {
    const message = this._nextMessageToSend.shift();
    return message;
  }

  /** the current status of this protocol */
  public protocolStatus(): ProtocolStatus {
    return this._protocolStatus;
  }

  public abstract processMessage(message: Message): boolean;
}

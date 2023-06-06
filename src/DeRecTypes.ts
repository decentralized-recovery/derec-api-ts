/*the protocols defined in RFC section 4 */
export enum ProtocolType {
  PAIRING_PROTOCOL,
  LOCKBOX_SHARES_UPDATE_PROTOCOL,
  KEEP_ALIVE_PROTOCOL,
  RECOVERY_PROTOCOL,
}

/*the current status of a given protocol state */
export enum ProtocolStatus {
  /*the protocol conversation hasn't yet started */
  NOT_STARTED = "Not Started",
  /*the protocol is currently ongoing (more messages will be needed) */
  ACTIVE = "Active",
  /*the protocol conversation finished successfully */
  DONE_SUCCESS = "Done Success",
  /*the protocol conversation failed (the only way to retry is to start a new conversation) */
  DONE_FAILURE = "Done Failure",
}

/*the message types defined in RFC section 5.1.1 */
export enum MessageType {
  PAIRING_REQUEST = 0x0000,
  PAIRING_RESPONSE = 0x0001,
  PAIRING_ACK = 0x0002,

  LOCKBOX_SHARE_RETRIEVAL_REQUEST = 0x0100,
  LOCKBOX_SHARE_RETREIVAL_RESPONSE = 0x0101,
  OPERATING_MODE_UPDATE = 0x0102,

  KEEP_ALIVE_REQUEST = 0x0200,
  KEEP_ALIVE_RESPONSE = 0x0201,

  STORE_LOCKBOX_SHARE_REQUEST = 0x0300,
  STORE_LOCKBOX_SHARE_RESPONSE = 0x0301,
  LOCKBOX_UPDATE_REQUEST = 0x0302,
}

export enum OperatingMode {
  NORMAL = 0x00,
  RECOVERY = 0xff,
}

using System;
using System.IO;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.util;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.tls
{

	
	public class DTLSReliableHandshake
	{
		private const int MAX_RECEIVE_AHEAD = 16;
		private const int MESSAGE_HEADER_LENGTH = 12;

		/*
		 * No 'final' modifiers so that it works in earlier JDKs
		 */
		private DTLSRecordLayer recordLayer;

		private TlsHandshakeHash handshakeHash;

		private Hashtable currentInboundFlight = new Hashtable();
		private Hashtable previousInboundFlight = null;
		private Vector outboundFlight = new Vector();
		private bool sending = true;

		private int message_seq = 0, next_receive_seq = 0;

		public DTLSReliableHandshake(TlsContext context, DTLSRecordLayer transport)
		{
			this.recordLayer = transport;
			this.handshakeHash = new DeferredHash();
			this.handshakeHash.init(context);
		}

		public virtual void notifyHelloComplete()
		{
			this.handshakeHash = handshakeHash.notifyPRFDetermined();
		}

		public virtual TlsHandshakeHash getHandshakeHash()
		{
			return handshakeHash;
		}

		public virtual TlsHandshakeHash prepareToFinish()
		{
			TlsHandshakeHash result = handshakeHash;
			this.handshakeHash = handshakeHash.stopTracking();
			return result;
		}

		public virtual void sendMessage(short msg_type, byte[] body)
		{
			TlsUtils.checkUint24(body.Length);

			if (!sending)
			{
				checkInboundFlight();
				sending = true;
				outboundFlight.removeAllElements();
			}

			Message message = new Message(message_seq++, msg_type, body);

			outboundFlight.addElement(message);

			writeMessage(message);
			updateHandshakeMessagesDigest(message);
		}

		public virtual byte[] receiveMessageBody(short msg_type)
		{
			Message message = receiveMessage();
			if (message.getType() != msg_type)
			{
				throw new TlsFatalAlert(AlertDescription.unexpected_message);
			}

			return message.getBody();
		}

		public virtual Message receiveMessage()
		{
			if (sending)
			{
				sending = false;
				prepareInboundFlight(new Hashtable());
			}

			byte[] buf = null;

			// TODO Check the conditions under which we should reset this
			int readTimeoutMillis = 1000;

			for (;;)
			{
				try
				{
					for (;;)
					{
						Message pending = getPendingMessage();
						if (pending != null)
						{
							return pending;
						}

						int receiveLimit = recordLayer.getReceiveLimit();
						if (buf == null || buf.Length < receiveLimit)
						{
							buf = new byte[receiveLimit];
						}

						int received = recordLayer.receive(buf, 0, receiveLimit, readTimeoutMillis);
						if (received < 0)
						{
							break;
						}

						bool resentOutbound = processRecord(MAX_RECEIVE_AHEAD, recordLayer.getReadEpoch(), buf, 0, received);
						if (resentOutbound)
						{
							readTimeoutMillis = backOff(readTimeoutMillis);
						}
					}
				}
				catch (IOException)
				{
					// NOTE: Assume this is a timeout for the moment
				}

				resendOutboundFlight();
				readTimeoutMillis = backOff(readTimeoutMillis);
			}
		}

		public virtual void finish()
		{
			DTLSHandshakeRetransmit retransmit = null;
			if (!sending)
			{
				checkInboundFlight();
			}
			else
			{
				prepareInboundFlight(null);

				if (previousInboundFlight != null)
				{
					/*
					 * RFC 6347 4.2.4. In addition, for at least twice the default MSL defined for [TCP],
					 * when in the FINISHED state, the node that transmits the last flight (the server in an
					 * ordinary handshake or the client in a resumed handshake) MUST respond to a retransmit
					 * of the peer's last flight with a retransmit of the last flight.
					 */
					retransmit = new DTLSHandshakeRetransmitAnonymousInnerClass(this);
				}
			}

			recordLayer.handshakeSuccessful(retransmit);
		}

		public class DTLSHandshakeRetransmitAnonymousInnerClass : DTLSHandshakeRetransmit
		{
			private readonly DTLSReliableHandshake outerInstance;

			public DTLSHandshakeRetransmitAnonymousInnerClass(DTLSReliableHandshake outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public void receivedHandshakeRecord(int epoch, byte[] buf, int off, int len)
			{
				outerInstance.processRecord(0, epoch, buf, off, len);
			}
		}

		public virtual void resetHandshakeMessagesDigest()
		{
			handshakeHash.reset();
		}

		private int backOff(int timeoutMillis)
		{
			/*
			 * TODO[DTLS] implementations SHOULD back off handshake packet size during the
			 * retransmit backoff.
			 */
			return Math.Min(timeoutMillis * 2, 60000);
		}

		/// <summary>
		/// Check that there are no "extra" messages left in the current inbound flight
		/// </summary>
		private void checkInboundFlight()
		{
			Enumeration e = currentInboundFlight.keys();
			while (e.hasMoreElements())
			{
				int? key = (int?)e.nextElement();
				if (key.Value >= next_receive_seq)
				{
					// TODO Should this be considered an error?
				}
			}
		}

		private Message getPendingMessage()
		{
			DTLSReassembler next = (DTLSReassembler)currentInboundFlight.get(Integers.valueOf(next_receive_seq));
			if (next != null)
			{
				byte[] body = next.getBodyIfComplete();
				if (body != null)
				{
					previousInboundFlight = null;
					return updateHandshakeMessagesDigest(new Message(next_receive_seq++, next.getMsgType(), body));
				}
			}
			return null;
		}

		private void prepareInboundFlight(Hashtable nextFlight)
		{
			resetAll(currentInboundFlight);
			previousInboundFlight = currentInboundFlight;
			currentInboundFlight = nextFlight;
		}

		private bool processRecord(int windowSize, int epoch, byte[] buf, int off, int len)
		{
			bool checkPreviousFlight = false;

			while (len >= MESSAGE_HEADER_LENGTH)
			{
				int fragment_length = TlsUtils.readUint24(buf, off + 9);
				int message_length = fragment_length + MESSAGE_HEADER_LENGTH;
				if (len < message_length)
				{
					// NOTE: Truncated message - ignore it
					break;
				}

				int length = TlsUtils.readUint24(buf, off + 1);
				int fragment_offset = TlsUtils.readUint24(buf, off + 6);
				if (fragment_offset + fragment_length > length)
				{
					// NOTE: Malformed fragment - ignore it and the rest of the record
					break;
				}

				/*
				 * NOTE: This very simple epoch check will only work until we want to support
				 * renegotiation (and we're not likely to do that anyway).
				 */
				short msg_type = TlsUtils.readUint8(buf, off + 0);
				int expectedEpoch = msg_type == HandshakeType.finished ? 1 : 0;
				if (epoch != expectedEpoch)
				{
					break;
				}

				int message_seq = TlsUtils.readUint16(buf, off + 4);
				if (message_seq >= (next_receive_seq + windowSize))
				{
					// NOTE: Too far ahead - ignore
				}
				else if (message_seq >= next_receive_seq)
				{
					DTLSReassembler reassembler = (DTLSReassembler)currentInboundFlight.get(Integers.valueOf(message_seq));
					if (reassembler == null)
					{
						reassembler = new DTLSReassembler(msg_type, length);
						currentInboundFlight.put(Integers.valueOf(message_seq), reassembler);
					}

					reassembler.contributeFragment(msg_type, length, buf, off + MESSAGE_HEADER_LENGTH, fragment_offset, fragment_length);
				}
				else if (previousInboundFlight != null)
				{
					/*
					 * NOTE: If we receive the previous flight of incoming messages in full again,
					 * retransmit our last flight
					 */

					DTLSReassembler reassembler = (DTLSReassembler)previousInboundFlight.get(Integers.valueOf(message_seq));
					if (reassembler != null)
					{
						reassembler.contributeFragment(msg_type, length, buf, off + MESSAGE_HEADER_LENGTH, fragment_offset, fragment_length);
						checkPreviousFlight = true;
					}
				}

				off += message_length;
				len -= message_length;
			}

			bool result = checkPreviousFlight && checkAll(previousInboundFlight);
			if (result)
			{
				resendOutboundFlight();
				resetAll(previousInboundFlight);
			}
			return result;
		}

		private void resendOutboundFlight()
		{
			recordLayer.resetWriteEpoch();
			for (int i = 0; i < outboundFlight.size(); ++i)
			{
				writeMessage((Message)outboundFlight.elementAt(i));
			}
		}

		private Message updateHandshakeMessagesDigest(Message message)
		{
			if (message.getType() != HandshakeType.hello_request)
			{
				byte[] body = message.getBody();
				byte[] buf = new byte[MESSAGE_HEADER_LENGTH];
				TlsUtils.writeUint8(message.getType(), buf, 0);
				TlsUtils.writeUint24(body.Length, buf, 1);
				TlsUtils.writeUint16(message.getSeq(), buf, 4);
				TlsUtils.writeUint24(0, buf, 6);
				TlsUtils.writeUint24(body.Length, buf, 9);
				handshakeHash.update(buf, 0, buf.Length);
				handshakeHash.update(body, 0, body.Length);
			}
			return message;
		}

		private void writeMessage(Message message)
		{
			int sendLimit = recordLayer.getSendLimit();
			int fragmentLimit = sendLimit - MESSAGE_HEADER_LENGTH;

			// TODO Support a higher minimum fragment size?
			if (fragmentLimit < 1)
			{
				// TODO Should we be throwing an exception here?
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}

			int length = message.getBody().Length;

			// NOTE: Must still send a fragment if body is empty
			int fragment_offset = 0;
			do
			{
				int fragment_length = Math.Min(length - fragment_offset, fragmentLimit);
				writeHandshakeFragment(message, fragment_offset, fragment_length);
				fragment_offset += fragment_length;
			} while (fragment_offset < length);
		}

		private void writeHandshakeFragment(Message message, int fragment_offset, int fragment_length)
		{
			RecordLayerBuffer fragment = new RecordLayerBuffer(MESSAGE_HEADER_LENGTH + fragment_length);
			TlsUtils.writeUint8(message.getType(), fragment);
			TlsUtils.writeUint24(message.getBody().Length, fragment);
			TlsUtils.writeUint16(message.getSeq(), fragment);
			TlsUtils.writeUint24(fragment_offset, fragment);
			TlsUtils.writeUint24(fragment_length, fragment);
			fragment.write(message.getBody(), fragment_offset, fragment_length);

			fragment.sendToRecordLayer(recordLayer);
		}

		private static bool checkAll(Hashtable inboundFlight)
		{
			Enumeration e = inboundFlight.elements();
			while (e.hasMoreElements())
			{
				if (((DTLSReassembler)e.nextElement()).getBodyIfComplete() == null)
				{
					return false;
				}
			}
			return true;
		}

		private static void resetAll(Hashtable inboundFlight)
		{
			Enumeration e = inboundFlight.elements();
			while (e.hasMoreElements())
			{
				((DTLSReassembler)e.nextElement()).reset();
			}
		}

		public class Message
		{
			internal readonly int message_seq;
			internal readonly short msg_type;
			internal readonly byte[] body;

			public Message(int message_seq, short msg_type, byte[] body)
			{
				this.message_seq = message_seq;
				this.msg_type = msg_type;
				this.body = body;
			}

			public virtual int getSeq()
			{
				return message_seq;
			}

			public virtual short getType()
			{
				return msg_type;
			}

			public virtual byte[] getBody()
			{
				return body;
			}
		}

		public class RecordLayerBuffer : ByteArrayOutputStream
		{
			public RecordLayerBuffer(int size) : base(size)
			{
			}

			public virtual void sendToRecordLayer(DTLSRecordLayer recordLayer)
			{
				recordLayer.send(buf, 0, count());
				//PORT: buf = null;
			}
		}
	}

}
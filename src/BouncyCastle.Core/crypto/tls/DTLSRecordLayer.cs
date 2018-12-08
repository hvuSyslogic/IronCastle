using System;
using System.IO;
using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.tls
{

	public class DTLSRecordLayer : DatagramTransport
	{
		private const int RECORD_HEADER_LENGTH = 13;
		private static readonly int MAX_FRAGMENT_LENGTH = 1 << 14;
		private static readonly long TCP_MSL = 1000L * 60 * 2;
		private static readonly long RETRANSMIT_TIMEOUT = TCP_MSL * 2;

		private readonly DatagramTransport transport;
		private readonly TlsContext context;
		private readonly TlsPeer peer;

		private readonly ByteQueue recordQueue = new ByteQueue();

		private volatile bool closed = false;
//JAVA TO C# CONVERTER NOTE: Fields cannot have the same name as methods:
		private volatile bool failed_Renamed = false;
		private volatile ProtocolVersion readVersion = null, writeVersion = null;
		private volatile bool inHandshake;
		private volatile int plaintextLimit;
		private DTLSEpoch currentEpoch, pendingEpoch;
		private DTLSEpoch readEpoch, writeEpoch;

		private DTLSHandshakeRetransmit retransmit = null;
		private DTLSEpoch retransmitEpoch = null;
		private long retransmitExpiry = 0;

		public DTLSRecordLayer(DatagramTransport transport, TlsContext context, TlsPeer peer, short contentType)
		{
			this.transport = transport;
			this.context = context;
			this.peer = peer;

			this.inHandshake = true;

			this.currentEpoch = new DTLSEpoch(0, new TlsNullCipher(context));
			this.pendingEpoch = null;
			this.readEpoch = currentEpoch;
			this.writeEpoch = currentEpoch;

			setPlaintextLimit(MAX_FRAGMENT_LENGTH);
		}

		public virtual void setPlaintextLimit(int plaintextLimit)
		{
			this.plaintextLimit = plaintextLimit;
		}

		public virtual int getReadEpoch()
		{
			return readEpoch.getEpoch();
		}

		public virtual ProtocolVersion getReadVersion()
		{
			return readVersion;
		}

		public virtual void setReadVersion(ProtocolVersion readVersion)
		{
			this.readVersion = readVersion;
		}

		public virtual void setWriteVersion(ProtocolVersion writeVersion)
		{
			this.writeVersion = writeVersion;
		}

		public virtual void initPendingEpoch(TlsCipher pendingCipher)
		{
			if (pendingEpoch != null)
			{
				throw new IllegalStateException();
			}

			/*
			 * TODO "In order to ensure that any given sequence/epoch pair is unique, implementations
			 * MUST NOT allow the same epoch value to be reused within two times the TCP maximum segment
			 * lifetime."
			 */

			// TODO Check for overflow
			this.pendingEpoch = new DTLSEpoch(writeEpoch.getEpoch() + 1, pendingCipher);
		}

		public virtual void handshakeSuccessful(DTLSHandshakeRetransmit retransmit)
		{
			if (readEpoch == currentEpoch || writeEpoch == currentEpoch)
			{
				// TODO
				throw new IllegalStateException();
			}

			if (retransmit != null)
			{
				this.retransmit = retransmit;
				this.retransmitEpoch = currentEpoch;
				this.retransmitExpiry = JavaSystem.currentTimeMillis() + RETRANSMIT_TIMEOUT;
			}

			this.inHandshake = false;
			this.currentEpoch = pendingEpoch;
			this.pendingEpoch = null;
		}

		public virtual void resetWriteEpoch()
		{
			if (retransmitEpoch != null)
			{
				this.writeEpoch = retransmitEpoch;
			}
			else
			{
				this.writeEpoch = currentEpoch;
			}
		}

		public virtual int getReceiveLimit()
		{
			return Math.Min(this.plaintextLimit, readEpoch.getCipher().getPlaintextLimit(transport.getReceiveLimit() - RECORD_HEADER_LENGTH));
		}

		public virtual int getSendLimit()
		{
			return Math.Min(this.plaintextLimit, writeEpoch.getCipher().getPlaintextLimit(transport.getSendLimit() - RECORD_HEADER_LENGTH));
		}

		public virtual int receive(byte[] buf, int off, int len, int waitMillis)
		{
			byte[] record = null;

			for (;;)
			{
				int receiveLimit = Math.Min(len, getReceiveLimit()) + RECORD_HEADER_LENGTH;
				if (record == null || record.Length < receiveLimit)
				{
					record = new byte[receiveLimit];
				}

				try
				{
					if (retransmit != null && JavaSystem.currentTimeMillis() > retransmitExpiry)
					{
						retransmit = null;
						retransmitEpoch = null;
					}

					int received = receiveRecord(record, 0, receiveLimit, waitMillis);
					if (received < 0)
					{
						return received;
					}
					if (received < RECORD_HEADER_LENGTH)
					{
						continue;
					}
					int length = TlsUtils.readUint16(record, 11);
					if (received != (length + RECORD_HEADER_LENGTH))
					{
						continue;
					}

					short type = TlsUtils.readUint8(record, 0);

					// TODO Support user-specified custom protocols?
					switch (type)
					{
					case ContentType.alert:
					case ContentType.application_data:
					case ContentType.change_cipher_spec:
					case ContentType.handshake:
					case ContentType.heartbeat:
						break;
					default:
						// TODO Exception?
						continue;
					}

					int epoch = TlsUtils.readUint16(record, 3);

					DTLSEpoch recordEpoch = null;
					if (epoch == readEpoch.getEpoch())
					{
						recordEpoch = readEpoch;
					}
					else if (type == ContentType.handshake && retransmitEpoch != null && epoch == retransmitEpoch.getEpoch())
					{
						recordEpoch = retransmitEpoch;
					}

					if (recordEpoch == null)
					{
						continue;
					}

					long seq = TlsUtils.readUint48(record, 5);
					if (recordEpoch.getReplayWindow().shouldDiscard(seq))
					{
						continue;
					}

					ProtocolVersion version = TlsUtils.readVersion(record, 1);
					if (!version.isDTLS())
					{
						continue;
					}

					if (readVersion != null && !readVersion.Equals(version))
					{
						continue;
					}

					byte[] plaintext = recordEpoch.getCipher().decodeCiphertext(getMacSequenceNumber(recordEpoch.getEpoch(), seq), type, record, RECORD_HEADER_LENGTH, received - RECORD_HEADER_LENGTH);

					recordEpoch.getReplayWindow().reportAuthenticated(seq);

					if (plaintext.Length > this.plaintextLimit)
					{
						continue;
					}

					if (readVersion == null)
					{
						readVersion = version;
					}

					switch (type)
					{
					case ContentType.alert:
					{
						if (plaintext.Length == 2)
						{
							short alertLevel = plaintext[0];
							short alertDescription = plaintext[1];

							peer.notifyAlertReceived(alertLevel, alertDescription);

							if (alertLevel == AlertLevel.fatal)
							{
								failed();
								throw new TlsFatalAlert(alertDescription);
							}

							// TODO Can close_notify be a fatal alert?
							if (alertDescription == AlertDescription.close_notify)
							{
								closeTransport();
							}
						}

						continue;
					}
					case ContentType.application_data:
					{
						if (inHandshake)
						{
							// TODO Consider buffering application data for new epoch that arrives
							// out-of-order with the Finished message
							continue;
						}
						break;
					}
					case ContentType.change_cipher_spec:
					{
						// Implicitly receive change_cipher_spec and change to pending cipher state

						for (int i = 0; i < plaintext.Length; ++i)
						{
							short message = TlsUtils.readUint8(plaintext, i);
							if (message != ChangeCipherSpec.change_cipher_spec)
							{
								continue;
							}

							if (pendingEpoch != null)
							{
								readEpoch = pendingEpoch;
							}
						}

						continue;
					}
					case ContentType.handshake:
					{
						if (!inHandshake)
						{
							if (retransmit != null)
							{
								retransmit.receivedHandshakeRecord(epoch, plaintext, 0, plaintext.Length);
							}

							// TODO Consider support for HelloRequest
							continue;
						}
						break;
					}
					case ContentType.heartbeat:
					{
						// TODO[RFC 6520]
						continue;
					}
					}

					/*
					 * NOTE: If we receive any non-handshake data in the new epoch implies the peer has
					 * received our final flight.
					 */
					if (!inHandshake && retransmit != null)
					{
						this.retransmit = null;
						this.retransmitEpoch = null;
					}

					JavaSystem.arraycopy(plaintext, 0, buf, off, plaintext.Length);
					return plaintext.Length;
				}
				catch (IOException e)
				{
					// NOTE: Assume this is a timeout for the moment
					throw;
				}
			}
		}

		public virtual void send(byte[] buf, int off, int len)
		{
			short contentType = ContentType.application_data;

			if (this.inHandshake || this.writeEpoch == this.retransmitEpoch)
			{
				contentType = ContentType.handshake;

				short handshakeType = TlsUtils.readUint8(buf, off);
				if (handshakeType == HandshakeType.finished)
				{
					DTLSEpoch nextEpoch = null;
					if (this.inHandshake)
					{
						nextEpoch = pendingEpoch;
					}
					else if (this.writeEpoch == this.retransmitEpoch)
					{
						nextEpoch = currentEpoch;
					}

					if (nextEpoch == null)
					{
						// TODO
						throw new IllegalStateException();
					}

					// Implicitly send change_cipher_spec and change to pending cipher state

					// TODO Send change_cipher_spec and finished records in single datagram?
					byte[] data = new byte[]{1};
					sendRecord(ContentType.change_cipher_spec, data, 0, data.Length);

					writeEpoch = nextEpoch;
				}
			}

			sendRecord(contentType, buf, off, len);
		}

		public virtual void close()
		{
			if (!closed)
			{
				if (inHandshake)
				{
					warn(AlertDescription.user_canceled, "User canceled handshake");
				}
				closeTransport();
			}
		}

		public virtual void fail(short alertDescription)
		{
			if (!closed)
			{
				try
				{
					raiseAlert(AlertLevel.fatal, alertDescription, null, null);
				}
				catch (Exception)
				{
					// Ignore
				}

				failed_Renamed = true;

				closeTransport();
			}
		}

		public virtual void failed()
		{
			if (!closed)
			{
				failed_Renamed = true;

				closeTransport();
			}
		}

		public virtual void warn(short alertDescription, string message)
		{
			raiseAlert(AlertLevel.warning, alertDescription, message, null);
		}

		private void closeTransport()
		{
			if (!closed)
			{
				/*
				 * RFC 5246 7.2.1. Unless some other fatal alert has been transmitted, each party is
				 * required to send a close_notify alert before closing the write side of the
				 * connection. The other party MUST respond with a close_notify alert of its own and
				 * close down the connection immediately, discarding any pending writes.
				 */

				try
				{
					if (!failed_Renamed)
					{
						warn(AlertDescription.close_notify, null);
					}
					transport.close();
				}
				catch (Exception)
				{
					// Ignore
				}

				closed = true;
			}
		}

		private void raiseAlert(short alertLevel, short alertDescription, string message, Exception cause)
		{
			peer.notifyAlertRaised(alertLevel, alertDescription, message, cause);

			byte[] error = new byte[2];
			error[0] = (byte)alertLevel;
			error[1] = (byte)alertDescription;

			sendRecord(ContentType.alert, error, 0, 2);
		}

		private int receiveRecord(byte[] buf, int off, int len, int waitMillis)
		{
			if (recordQueue.available() > 0)
			{
				int length = 0;
				if (recordQueue.available() >= RECORD_HEADER_LENGTH)
				{
					byte[] lengthBytes = new byte[2];
					recordQueue.read(lengthBytes, 0, 2, 11);
					length = TlsUtils.readUint16(lengthBytes, 0);
				}

				int received = Math.Min(recordQueue.available(), RECORD_HEADER_LENGTH + length);
				recordQueue.removeData(buf, off, received, 0);
				return received;
			}

			int received = transport.receive(buf, off, len, waitMillis);
			if (received >= RECORD_HEADER_LENGTH)
			{
				int fragmentLength = TlsUtils.readUint16(buf, off + 11);
				int recordLength = RECORD_HEADER_LENGTH + fragmentLength;
				if (received > recordLength)
				{
					recordQueue.addData(buf, off + recordLength, received - recordLength);
					received = recordLength;
				}
			}

			return received;
		}

		private void sendRecord(short contentType, byte[] buf, int off, int len)
		{
			// Never send anything until a valid ClientHello has been received
			if (writeVersion == null)
			{
				return;
			}

			if (len > this.plaintextLimit)
			{
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}

			/*
			 * RFC 5246 6.2.1 Implementations MUST NOT send zero-length fragments of Handshake, Alert,
			 * or ChangeCipherSpec content types.
			 */
			if (len < 1 && contentType != ContentType.application_data)
			{
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}

			int recordEpoch = writeEpoch.getEpoch();
			long recordSequenceNumber = writeEpoch.allocateSequenceNumber();

			byte[] ciphertext = writeEpoch.getCipher().encodePlaintext(getMacSequenceNumber(recordEpoch, recordSequenceNumber), contentType, buf, off, len);

			// TODO Check the ciphertext length?

			byte[] record = new byte[ciphertext.Length + RECORD_HEADER_LENGTH];
			TlsUtils.writeUint8(contentType, record, 0);
			TlsUtils.writeVersion(writeVersion, record, 1);
			TlsUtils.writeUint16(recordEpoch, record, 3);
			TlsUtils.writeUint48(recordSequenceNumber, record, 5);
			TlsUtils.writeUint16(ciphertext.Length, record, 11);
			JavaSystem.arraycopy(ciphertext, 0, record, RECORD_HEADER_LENGTH, ciphertext.Length);

			transport.send(record, 0, record.Length);
		}

		private static long getMacSequenceNumber(int epoch, long sequence_number)
		{
			return ((epoch & 0xFFFFFFFFL) << 48) | sequence_number;
		}
	}

}
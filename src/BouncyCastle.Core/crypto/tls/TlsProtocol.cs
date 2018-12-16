using System;
using System.IO;
using BouncyCastle.Core.Port;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.crypto.tls
{

	using RandomGenerator = org.bouncycastle.crypto.prng.RandomGenerator;
	using Arrays = org.bouncycastle.util.Arrays;
	using Integers = org.bouncycastle.util.Integers;

	public abstract class TlsProtocol
	{
		protected internal static readonly int? EXT_RenegotiationInfo = Integers.valueOf(ExtensionType.renegotiation_info);
		protected internal static readonly int? EXT_SessionTicket = Integers.valueOf(ExtensionType.session_ticket);

		/*
		 * Our Connection states
		 */
		protected internal const short CS_START = 0;
		protected internal const short CS_CLIENT_HELLO = 1;
		protected internal const short CS_SERVER_HELLO = 2;
		protected internal const short CS_SERVER_SUPPLEMENTAL_DATA = 3;
		protected internal const short CS_SERVER_CERTIFICATE = 4;
		protected internal const short CS_CERTIFICATE_STATUS = 5;
		protected internal const short CS_SERVER_KEY_EXCHANGE = 6;
		protected internal const short CS_CERTIFICATE_REQUEST = 7;
		protected internal const short CS_SERVER_HELLO_DONE = 8;
		protected internal const short CS_CLIENT_SUPPLEMENTAL_DATA = 9;
		protected internal const short CS_CLIENT_CERTIFICATE = 10;
		protected internal const short CS_CLIENT_KEY_EXCHANGE = 11;
		protected internal const short CS_CERTIFICATE_VERIFY = 12;
		protected internal const short CS_CLIENT_FINISHED = 13;
		protected internal const short CS_SERVER_SESSION_TICKET = 14;
		protected internal const short CS_SERVER_FINISHED = 15;
		protected internal const short CS_END = 16;

		/*
		 * Different modes to handle the known IV weakness
		 */
		protected internal const short ADS_MODE_1_Nsub1 = 0; // 1/n-1 record splitting
		protected internal const short ADS_MODE_0_N = 1; // 0/n record splitting
		protected internal const short ADS_MODE_0_N_FIRSTONLY = 2; // 0/n record splitting on first data fragment only

		/*
		 * Queues for data from some protocols.
		 */
		private ByteQueue applicationDataQueue = new ByteQueue(0);
		private ByteQueue alertQueue = new ByteQueue(2);
		private ByteQueue handshakeQueue = new ByteQueue(0);
	//    private ByteQueue heartbeatQueue = new ByteQueue();

		/*
		 * The Record Stream we use
		 */
		internal RecordStream recordStream;
		protected internal SecureRandom secureRandom;

		private TlsInputStream tlsInputStream = null;
		private TlsOutputStream tlsOutputStream = null;

		private volatile bool closed = false;
		private volatile bool failedWithError = false;
		private volatile bool appDataReady = false;
		private volatile bool appDataSplitEnabled = true;
		private volatile int appDataSplitMode = ADS_MODE_1_Nsub1;
		private byte[] expected_verify_data = null;

		protected internal TlsSession tlsSession = null;
		protected internal SessionParameters sessionParameters = null;
		protected internal SecurityParameters securityParameters = null;
		protected internal Certificate peerCertificate = null;

		protected internal int[] offeredCipherSuites = null;
		protected internal short[] offeredCompressionMethods = null;
		protected internal Hashtable clientExtensions = null;
		protected internal Hashtable serverExtensions = null;

		protected internal short connection_state = CS_START;
		protected internal bool resumedSession = false;
		protected internal bool receivedChangeCipherSpec = false;
		protected internal bool secure_renegotiation = false;
		protected internal bool allowCertificateStatus = false;
		protected internal bool expectSessionTicket = false;

		protected internal bool blocking;
		protected internal ByteQueueInputStream inputBuffers;
		protected internal ByteQueueOutputStream outputBuffer;

		public TlsProtocol(InputStream input, OutputStream output, SecureRandom secureRandom)
		{
			this.blocking = true;
			this.recordStream = new RecordStream(this, input, output);
			this.secureRandom = secureRandom;
		}

		public TlsProtocol(SecureRandom secureRandom)
		{
			this.blocking = false;
			this.inputBuffers = new ByteQueueInputStream();
			this.outputBuffer = new ByteQueueOutputStream();
			this.recordStream = new RecordStream(this, inputBuffers, outputBuffer);
			this.secureRandom = secureRandom;
		}

		public abstract TlsContext getContext();

		public abstract AbstractTlsContext getContextAdmin();

		public abstract TlsPeer getPeer();

		public virtual void handleAlertMessage(short alertLevel, short alertDescription)
		{
			getPeer().notifyAlertReceived(alertLevel, alertDescription);

			if (alertLevel == AlertLevel.warning)
			{
				handleAlertWarningMessage(alertDescription);
			}
			else
			{
				handleFailure();

				throw new TlsFatalAlertReceived(alertDescription);
			}
		}

		public virtual void handleAlertWarningMessage(short alertDescription)
		{
			/*
			 * RFC 5246 7.2.1. The other party MUST respond with a close_notify alert of its own
			 * and close down the connection immediately, discarding any pending writes.
			 */
			if (alertDescription == AlertDescription.close_notify)
			{
				if (!appDataReady)
				{
					throw new TlsFatalAlert(AlertDescription.handshake_failure);
				}
				handleClose(false);
			}
		}

		public virtual void handleChangeCipherSpecMessage()
		{
		}

		public virtual void handleClose(bool user_canceled)
		{
			if (!closed)
			{
				this.closed = true;

				if (user_canceled && !appDataReady)
				{
					raiseAlertWarning(AlertDescription.user_canceled, "User canceled handshake");
				}

				raiseAlertWarning(AlertDescription.close_notify, "Connection closed");

				recordStream.safeClose();

				if (!appDataReady)
				{
					cleanupHandshake();
				}
			}
		}

		public virtual void handleException(short alertDescription, string message, Exception cause)
		{
			if (!closed)
			{
				raiseAlertFatal(alertDescription, message, cause);

				handleFailure();
			}
		}

		public virtual void handleFailure()
		{
			this.closed = true;
			this.failedWithError = true;

			/*
			 * RFC 2246 7.2.1. The session becomes unresumable if any connection is terminated
			 * without proper close_notify messages with level equal to warning.
			 */
			// TODO This isn't quite in the right place. Also, as of TLS 1.1 the above is obsolete.
			invalidateSession();

			recordStream.safeClose();

			if (!appDataReady)
			{
				cleanupHandshake();
			}
		}

		public abstract void handleHandshakeMessage(short type, ByteArrayInputStream buf);

		public virtual void applyMaxFragmentLengthExtension()
		{
			if (securityParameters.maxFragmentLength >= 0)
			{
				if (!MaxFragmentLength.isValid(securityParameters.maxFragmentLength))
				{
					throw new TlsFatalAlert(AlertDescription.internal_error);
				}

				int plainTextLimit = 1 << (8 + securityParameters.maxFragmentLength);
				recordStream.setPlaintextLimit(plainTextLimit);
			}
		}

		public virtual void checkReceivedChangeCipherSpec(bool expected)
		{
			if (expected != receivedChangeCipherSpec)
			{
				throw new TlsFatalAlert(AlertDescription.unexpected_message);
			}
		}

		public virtual void cleanupHandshake()
		{
			if (this.expected_verify_data != null)
			{
				Arrays.fill(this.expected_verify_data, (byte)0);
				this.expected_verify_data = null;
			}

			this.securityParameters.clear();
			this.peerCertificate = null;

			this.offeredCipherSuites = null;
			this.offeredCompressionMethods = null;
			this.clientExtensions = null;
			this.serverExtensions = null;

			this.resumedSession = false;
			this.receivedChangeCipherSpec = false;
			this.secure_renegotiation = false;
			this.allowCertificateStatus = false;
			this.expectSessionTicket = false;
		}

		public virtual void blockForHandshake()
		{
			if (blocking)
			{
				while (this.connection_state != CS_END)
				{
					if (this.closed)
					{
						// NOTE: Any close during the handshake should have raised an exception.
						throw new TlsFatalAlert(AlertDescription.internal_error);
					}

					safeReadRecord();
				}
			}
		}

		public virtual void completeHandshake()
		{
			try
			{
				this.connection_state = CS_END;

				this.alertQueue.shrink();
				this.handshakeQueue.shrink();

				this.recordStream.finaliseHandshake();

				this.appDataSplitEnabled = !TlsUtils.isTLSv11(getContext());

				/*
				 * If this was an initial handshake, we are now ready to send and receive application data.
				 */
				if (!appDataReady)
				{
					this.appDataReady = true;

					if (blocking)
					{
						this.tlsInputStream = new TlsInputStream(this);
						this.tlsOutputStream = new TlsOutputStream(this);
					}
				}

				if (this.tlsSession != null)
				{
					if (this.sessionParameters == null)
					{
						this.sessionParameters = (new SessionParameters.Builder()).setCipherSuite(this.securityParameters.getCipherSuite()).setCompressionAlgorithm(this.securityParameters.getCompressionAlgorithm()).setExtendedMasterSecret(securityParameters.isExtendedMasterSecret()).setMasterSecret(this.securityParameters.getMasterSecret()).setPeerCertificate(this.peerCertificate).setPSKIdentity(this.securityParameters.getPSKIdentity()).setSRPIdentity(this.securityParameters.getSRPIdentity()).setServerExtensions(this.serverExtensions).build();

						this.tlsSession = new TlsSessionImpl(this.tlsSession.getSessionID(), this.sessionParameters);
					}

					getContextAdmin().setResumableSession(this.tlsSession);
				}

				getPeer().notifyHandshakeComplete();
			}
			finally
			{
				cleanupHandshake();
			}
		}

		public virtual void processRecord(short protocol, byte[] buf, int off, int len)
		{
			/*
			 * Have a look at the protocol type, and add it to the correct queue.
			 */
			switch (protocol)
			{
			case ContentType.alert:
			{
				alertQueue.addData(buf, off, len);
				processAlertQueue();
				break;
			}
			case ContentType.application_data:
			{
				if (!appDataReady)
				{
					throw new TlsFatalAlert(AlertDescription.unexpected_message);
				}
				applicationDataQueue.addData(buf, off, len);
				processApplicationDataQueue();
				break;
			}
			case ContentType.change_cipher_spec:
			{
				processChangeCipherSpec(buf, off, len);
				break;
			}
			case ContentType.handshake:
			{
				if (handshakeQueue.available() > 0)
				{
					handshakeQueue.addData(buf, off, len);
					processHandshakeQueue(handshakeQueue);
				}
				else
				{
					ByteQueue tmpQueue = new ByteQueue(buf, off, len);
					processHandshakeQueue(tmpQueue);
					int remaining = tmpQueue.available();
					if (remaining > 0)
					{
						handshakeQueue.addData(buf, off + len - remaining, remaining);
					}
				}
				break;
			}
	//        case ContentType.heartbeat:
	//        {
	//            if (!appDataReady)
	//            {
	//                throw new TlsFatalAlert(AlertDescription.unexpected_message);
	//            }
	//            // TODO[RFC 6520]
	////            heartbeatQueue.addData(buf, offset, len);
	////            processHeartbeat();
	//            break;
	//        }
			default:
				// Record type should already have been checked
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}
		}

		private void processHandshakeQueue(ByteQueue queue)
		{
			while (queue.available() >= 4)
			{
				/*
				 * We need the first 4 bytes, they contain type and length of the message.
				 */
				byte[] beginning = new byte[4];
				queue.read(beginning, 0, 4, 0);
				short type = TlsUtils.readUint8(beginning, 0);
				int length = TlsUtils.readUint24(beginning, 1);
				int totalLength = 4 + length;

				/*
				 * Check if we have enough bytes in the buffer to read the full message.
				 */
				if (queue.available() < totalLength)
				{
					break;
				}

				/*
				 * RFC 2246 7.4.9. The value handshake_messages includes all handshake messages
				 * starting at client hello up to, but not including, this finished message.
				 * [..] Note: [Also,] Hello Request messages are omitted from handshake hashes.
				 */
				if (HandshakeType.hello_request != type)
				{
					if (HandshakeType.finished == type)
					{
						checkReceivedChangeCipherSpec(true);

						TlsContext ctx = getContext();
						if (this.expected_verify_data == null && ctx.getSecurityParameters().getMasterSecret() != null)
						{
							this.expected_verify_data = createVerifyData(!ctx.isServer());
						}
					}
					else
					{
						checkReceivedChangeCipherSpec(connection_state == CS_END);
					}

					queue.copyTo(recordStream.getHandshakeHashUpdater(), totalLength);
				}

				queue.removeData(4);

				ByteArrayInputStream buf = queue.readFrom(length);

				/*
				 * Now, parse the message.
				 */
				handleHandshakeMessage(type, buf);
			}
		}

		private void processApplicationDataQueue()
		{
			/*
			 * There is nothing we need to do here.
			 * 
			 * This function could be used for callbacks when application data arrives in the future.
			 */
		}

		private void processAlertQueue()
		{
			while (alertQueue.available() >= 2)
			{
				/*
				 * An alert is always 2 bytes. Read the alert.
				 */
				byte[] alert = alertQueue.removeData(2, 0);
				short alertLevel = alert[0];
				short alertDescription = alert[1];

				handleAlertMessage(alertLevel, alertDescription);
			}
		}

		/// <summary>
		/// This method is called, when a change cipher spec message is received.
		/// </summary>
		/// <exception cref="IOException"> If the message has an invalid content or the handshake is not in the correct
		/// state. </exception>
		private void processChangeCipherSpec(byte[] buf, int off, int len)
		{
			for (int i = 0; i < len; ++i)
			{
				short message = TlsUtils.readUint8(buf, off + i);

				if (message != ChangeCipherSpec.change_cipher_spec)
				{
					throw new TlsFatalAlert(AlertDescription.decode_error);
				}

				if (this.receivedChangeCipherSpec || alertQueue.available() > 0 || handshakeQueue.available() > 0)
				{
					throw new TlsFatalAlert(AlertDescription.unexpected_message);
				}

				recordStream.receivedReadCipherSpec();

				this.receivedChangeCipherSpec = true;

				handleChangeCipherSpecMessage();
			}
		}

		public virtual int applicationDataAvailable()
		{
			return applicationDataQueue.available();
		}

		/// <summary>
		/// Read data from the network. The method will return immediately, if there is still some data
		/// left in the buffer, or block until some application data has been read from the network.
		/// </summary>
		/// <param name="buf">    The buffer where the data will be copied to. </param>
		/// <param name="offset"> The position where the data will be placed in the buffer. </param>
		/// <param name="len">    The maximum number of bytes to read. </param>
		/// <returns> The number of bytes read. </returns>
		/// <exception cref="IOException"> If something goes wrong during reading data. </exception>
		public virtual int readApplicationData(byte[] buf, int offset, int len)
		{
			if (len < 1)
			{
				return 0;
			}

			while (applicationDataQueue.available() == 0)
			{
				if (this.closed)
				{
					if (this.failedWithError)
					{
						throw new IOException("Cannot read application data on failed TLS connection");
					}
					if (!appDataReady)
					{
						throw new IllegalStateException("Cannot read application data until initial handshake completed.");
					}

					return -1;
				}

				safeReadRecord();
			}

			len = Math.Min(len, applicationDataQueue.available());
			applicationDataQueue.removeData(buf, offset, len, 0);
			return len;
		}

		public virtual void safeCheckRecordHeader(byte[] recordHeader)
		{
			try
			{
				recordStream.checkRecordHeader(recordHeader);
			}
			catch (TlsFatalAlert e)
			{
				handleException(e.getAlertDescription(), "Failed to read record", e);
				throw e;
			}
			catch (IOException e)
			{
				handleException(AlertDescription.internal_error, "Failed to read record", e);
				throw e;
			}
			catch (RuntimeException e)
			{
				handleException(AlertDescription.internal_error, "Failed to read record", e);
				throw new TlsFatalAlert(AlertDescription.internal_error, e);
			}
		}

		public virtual void safeReadRecord()
		{
			try
			{
				if (recordStream.readRecord())
				{
					return;
				}

				if (!appDataReady)
				{
					throw new TlsFatalAlert(AlertDescription.handshake_failure);
				}
			}
			catch (TlsFatalAlertReceived e)
			{
				// Connection failure already handled at source
				throw e;
			}
			catch (TlsFatalAlert e)
			{
				handleException(e.getAlertDescription(), "Failed to read record", e);
				throw e;
			}
			catch (IOException e)
			{
				handleException(AlertDescription.internal_error, "Failed to read record", e);
				throw e;
			}
			catch (RuntimeException e)
			{
				handleException(AlertDescription.internal_error, "Failed to read record", e);
				throw new TlsFatalAlert(AlertDescription.internal_error, e);
			}

			handleFailure();

			throw new TlsNoCloseNotifyException();
		}

		public virtual void safeWriteRecord(short type, byte[] buf, int offset, int len)
		{
			try
			{
				recordStream.writeRecord(type, buf, offset, len);
			}
			catch (TlsFatalAlert e)
			{
				handleException(e.getAlertDescription(), "Failed to write record", e);
				throw e;
			}
			catch (IOException e)
			{
				handleException(AlertDescription.internal_error, "Failed to write record", e);
				throw e;
			}
			catch (RuntimeException e)
			{
				handleException(AlertDescription.internal_error, "Failed to write record", e);
				throw new TlsFatalAlert(AlertDescription.internal_error, e);
			}
		}

		/// <summary>
		/// Send some application data to the remote system.
		/// <para>
		/// The method will handle fragmentation internally.
		/// </para> </summary>
		/// <param name="buf">    The buffer with the data. </param>
		/// <param name="offset"> The position in the buffer where the data is placed. </param>
		/// <param name="len">    The length of the data. </param>
		/// <exception cref="IOException"> If something goes wrong during sending. </exception>
		public virtual void writeData(byte[] buf, int offset, int len)
		{
			if (this.closed)
			{
				throw new IOException("Cannot write application data on closed/failed TLS connection");
			}

			while (len > 0)
			{
				/*
				 * RFC 5246 6.2.1. Zero-length fragments of Application data MAY be sent as they are
				 * potentially useful as a traffic analysis countermeasure.
				 * 
				 * NOTE: Actually, implementations appear to have settled on 1/n-1 record splitting.
				 */

				if (this.appDataSplitEnabled)
				{
					/*
					 * Protect against known IV attack!
					 * 
					 * DO NOT REMOVE THIS CODE, EXCEPT YOU KNOW EXACTLY WHAT YOU ARE DOING HERE.
					 */
					switch (appDataSplitMode)
					{
						case ADS_MODE_0_N_FIRSTONLY:
							this.appDataSplitEnabled = false;
							// fall through intended!
							goto case ADS_MODE_0_N;
						case ADS_MODE_0_N:
							safeWriteRecord(ContentType.application_data, TlsUtils.EMPTY_BYTES, 0, 0);
							break;
						case ADS_MODE_1_Nsub1:
						default:
							safeWriteRecord(ContentType.application_data, buf, offset, 1);
							++offset;
							--len;
							break;
					}
				}

				if (len > 0)
				{
					// Fragment data according to the current fragment limit.
					int toWrite = Math.Min(len, recordStream.getPlaintextLimit());
					safeWriteRecord(ContentType.application_data, buf, offset, toWrite);
					offset += toWrite;
					len -= toWrite;
				}
			}
		}

		public virtual void setAppDataSplitMode(int appDataSplitMode)
		{
			if (appDataSplitMode < ADS_MODE_1_Nsub1 || appDataSplitMode > ADS_MODE_0_N_FIRSTONLY)
			{
				throw new IllegalArgumentException("Illegal appDataSplitMode mode: " + appDataSplitMode);
			}
			this.appDataSplitMode = appDataSplitMode;
		}

		public virtual void writeHandshakeMessage(byte[] buf, int off, int len)
		{
			if (len < 4)
			{
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}

			short type = TlsUtils.readUint8(buf, off);
			if (type != HandshakeType.hello_request)
			{
				recordStream.getHandshakeHashUpdater().write(buf, off, len);
			}

			int total = 0;
			do
			{
				// Fragment data according to the current fragment limit.
				int toWrite = Math.Min(len - total, recordStream.getPlaintextLimit());
				safeWriteRecord(ContentType.handshake, buf, off + total, toWrite);
				total += toWrite;
			} while (total < len);
		}

		/// <returns> An OutputStream which can be used to send data. Only allowed in blocking mode. </returns>
		public virtual OutputStream getOutputStream()
		{
			if (!blocking)
			{
				throw new IllegalStateException("Cannot use OutputStream in non-blocking mode! Use offerOutput() instead.");
			}
			return this.tlsOutputStream;
		}

		/// <returns> An InputStream which can be used to read data. Only allowed in blocking mode. </returns>
		public virtual InputStream getInputStream()
		{
			if (!blocking)
			{
				throw new IllegalStateException("Cannot use InputStream in non-blocking mode! Use offerInput() instead.");
			}
			return this.tlsInputStream;
		}

		/// <summary>
		/// Should be called in non-blocking mode when the input data reaches EOF.
		/// </summary>
		public virtual void closeInput()
		{
			if (blocking)
			{
				throw new IllegalStateException("Cannot use closeInput() in blocking mode!");
			}

			if (closed)
			{
				return;
			}

			if (inputBuffers.available() > 0)
			{
				throw new EOFException();
			}

			if (!appDataReady)
			{
				throw new TlsFatalAlert(AlertDescription.handshake_failure);
			}

			throw new TlsNoCloseNotifyException();
		}

		/// <summary>
		/// Offer input from an arbitrary source. Only allowed in non-blocking mode.<br>
		/// <br>
		/// After this method returns, the input buffer is "owned" by this object. Other code
		/// must not attempt to do anything with it.<br>
		/// <br>
		/// This method will decrypt and process all records that are fully available.
		/// If only part of a record is available, the buffer will be retained until the
		/// remainder of the record is offered.<br>
		/// <br>
		/// If any records containing application data were processed, the decrypted data
		/// can be obtained using <seealso cref="#readInput(byte[], int, int)"/>. If any records
		/// containing protocol data were processed, a response may have been generated.
		/// You should always check to see if there is any available output after calling
		/// this method by calling <seealso cref="#getAvailableOutputBytes()"/>. </summary>
		/// <param name="input"> The input buffer to offer </param>
		/// <exception cref="IOException"> If an error occurs while decrypting or processing a record </exception>
		public virtual void offerInput(byte[] input)
		{
			if (blocking)
			{
				throw new IllegalStateException("Cannot use offerInput() in blocking mode! Use getInputStream() instead.");
			}

			if (closed)
			{
				throw new IOException("Connection is closed, cannot accept any more input");
			}

			inputBuffers.addBytes(input);

			// loop while there are enough bytes to read the length of the next record
			while (inputBuffers.available() >= RecordStream.TLS_HEADER_SIZE)
			{
				byte[] recordHeader = new byte[RecordStream.TLS_HEADER_SIZE];
				inputBuffers.peek(recordHeader);

				int totalLength = TlsUtils.readUint16(recordHeader, RecordStream.TLS_HEADER_LENGTH_OFFSET) + RecordStream.TLS_HEADER_SIZE;
				if (inputBuffers.available() < totalLength)
				{
					// not enough bytes to read a whole record
					safeCheckRecordHeader(recordHeader);
					break;
				}

				safeReadRecord();

				if (closed)
				{
					if (connection_state != CS_END)
					{
						// NOTE: Any close during the handshake should have raised an exception.
						throw new TlsFatalAlert(AlertDescription.internal_error);
					}
					break;
				}
			}
		}

		/// <summary>
		/// Gets the amount of received application data. A call to <seealso cref="#readInput(byte[], int, int)"/>
		/// is guaranteed to be able to return at least this much data.<br>
		/// <br>
		/// Only allowed in non-blocking mode. </summary>
		/// <returns> The number of bytes of available application data </returns>
		public virtual int getAvailableInputBytes()
		{
			if (blocking)
			{
				throw new IllegalStateException("Cannot use getAvailableInputBytes() in blocking mode! Use getInputStream().available() instead.");
			}
			return applicationDataAvailable();
		}

		/// <summary>
		/// Retrieves received application data. Use <seealso cref="#getAvailableInputBytes()"/> to check
		/// how much application data is currently available. This method functions similarly to
		/// <seealso cref="InputStream#read(byte[], int, int)"/>, except that it never blocks. If no data
		/// is available, nothing will be copied and zero will be returned.<br>
		/// <br>
		/// Only allowed in non-blocking mode. </summary>
		/// <param name="buffer"> The buffer to hold the application data </param>
		/// <param name="offset"> The start offset in the buffer at which the data is written </param>
		/// <param name="length"> The maximum number of bytes to read </param>
		/// <returns> The total number of bytes copied to the buffer. May be less than the
		///          length specified if the length was greater than the amount of available data. </returns>
		public virtual int readInput(byte[] buffer, int offset, int length)
		{
			if (blocking)
			{
				throw new IllegalStateException("Cannot use readInput() in blocking mode! Use getInputStream() instead.");
			}

			try
			{
				return readApplicationData(buffer, offset, Math.Min(length, applicationDataAvailable()));
			}
			catch (IOException e)
			{
				// readApplicationData() only throws if there is no data available, so this should never happen
				throw new RuntimeException(e.ToString()); // early JDK fix.
			}
		}

		/// <summary>
		/// Offer output from an arbitrary source. Only allowed in non-blocking mode.<br>
		/// <br>
		/// After this method returns, the specified section of the buffer will have been
		/// processed. Use <seealso cref="#readOutput(byte[], int, int)"/> to get the bytes to
		/// transmit to the other peer.<br>
		/// <br>
		/// This method must not be called until after the handshake is complete! Attempting
		/// to call it before the handshake is complete will result in an exception. </summary>
		/// <param name="buffer"> The buffer containing application data to encrypt </param>
		/// <param name="offset"> The offset at which to begin reading data </param>
		/// <param name="length"> The number of bytes of data to read </param>
		/// <exception cref="IOException"> If an error occurs encrypting the data, or the handshake is not complete </exception>
		public virtual void offerOutput(byte[] buffer, int offset, int length)
		{
			if (blocking)
			{
				throw new IllegalStateException("Cannot use offerOutput() in blocking mode! Use getOutputStream() instead.");
			}

			if (!appDataReady)
			{
				throw new IOException("Application data cannot be sent until the handshake is complete!");
			}

			writeData(buffer, offset, length);
		}

		/// <summary>
		/// Gets the amount of encrypted data available to be sent. A call to
		/// <seealso cref="#readOutput(byte[], int, int)"/> is guaranteed to be able to return at
		/// least this much data.<br>
		/// <br>
		/// Only allowed in non-blocking mode. </summary>
		/// <returns> The number of bytes of available encrypted data </returns>
		public virtual int getAvailableOutputBytes()
		{
			if (blocking)
			{
				throw new IllegalStateException("Cannot use getAvailableOutputBytes() in blocking mode! Use getOutputStream() instead.");
			}

			return outputBuffer.getBuffer().available();
		}

		/// <summary>
		/// Retrieves encrypted data to be sent. Use <seealso cref="#getAvailableOutputBytes()"/> to check
		/// how much encrypted data is currently available. This method functions similarly to
		/// <seealso cref="InputStream#read(byte[], int, int)"/>, except that it never blocks. If no data
		/// is available, nothing will be copied and zero will be returned.<br>
		/// <br>
		/// Only allowed in non-blocking mode. </summary>
		/// <param name="buffer"> The buffer to hold the encrypted data </param>
		/// <param name="offset"> The start offset in the buffer at which the data is written </param>
		/// <param name="length"> The maximum number of bytes to read </param>
		/// <returns> The total number of bytes copied to the buffer. May be less than the
		///          length specified if the length was greater than the amount of available data. </returns>
		public virtual int readOutput(byte[] buffer, int offset, int length)
		{
			if (blocking)
			{
				throw new IllegalStateException("Cannot use readOutput() in blocking mode! Use getOutputStream() instead.");
			}

			int bytesToRead = Math.Min(getAvailableOutputBytes(), length);
			outputBuffer.getBuffer().removeData(buffer, offset, bytesToRead, 0);
			return bytesToRead;
		}

		public virtual void invalidateSession()
		{
			if (this.sessionParameters != null)
			{
				this.sessionParameters.clear();
				this.sessionParameters = null;
			}

			if (this.tlsSession != null)
			{
				this.tlsSession.invalidate();
				this.tlsSession = null;
			}
		}

		public virtual void processFinishedMessage(ByteArrayInputStream buf)
		{
			if (expected_verify_data == null)
			{
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}

			byte[] verify_data = TlsUtils.readFully(expected_verify_data.Length, buf);

			assertEmpty(buf);

			/*
			 * Compare both checksums.
			 */
			if (!Arrays.constantTimeAreEqual(expected_verify_data, verify_data))
			{
				/*
				 * Wrong checksum in the finished message.
				 */
				throw new TlsFatalAlert(AlertDescription.decrypt_error);
			}
		}

		public virtual void raiseAlertFatal(short alertDescription, string message, Exception cause)
		{
			getPeer().notifyAlertRaised(AlertLevel.fatal, alertDescription, message, cause);

			byte[] alert = new byte[]{(byte)AlertLevel.fatal, (byte)alertDescription};

			try
			{
				recordStream.writeRecord(ContentType.alert, alert, 0, 2);
			}
			catch (Exception)
			{
				// We are already processing an exception, so just ignore this
			}
		}

		public virtual void raiseAlertWarning(short alertDescription, string message)
		{
			getPeer().notifyAlertRaised(AlertLevel.warning, alertDescription, message, null);

			byte[] alert = new byte[]{(byte)AlertLevel.warning, (byte)alertDescription};

			safeWriteRecord(ContentType.alert, alert, 0, 2);
		}

		public virtual void sendCertificateMessage(Certificate certificate)
		{
			if (certificate == null)
			{
				certificate = Certificate.EMPTY_CHAIN;
			}

			if (certificate.isEmpty())
			{
				TlsContext context = getContext();
				if (!context.isServer())
				{
					ProtocolVersion serverVersion = getContext().getServerVersion();
					if (serverVersion.isSSL())
					{
						string errorMessage = serverVersion.ToString() + " client didn't provide credentials";
						raiseAlertWarning(AlertDescription.no_certificate, errorMessage);
						return;
					}
				}
			}

			HandshakeMessage message = new HandshakeMessage(this, HandshakeType.certificate);

			certificate.encode(message);

			message.writeToRecordStream();
		}

		public virtual void sendChangeCipherSpecMessage()
		{
			byte[] message = new byte[]{1};
			safeWriteRecord(ContentType.change_cipher_spec, message, 0, message.Length);
			recordStream.sentWriteCipherSpec();
		}

		public virtual void sendFinishedMessage()
		{
			byte[] verify_data = createVerifyData(getContext().isServer());

			HandshakeMessage message = new HandshakeMessage(this, HandshakeType.finished, verify_data.Length);

			message.write(verify_data);

			message.writeToRecordStream();
		}

		public virtual void sendSupplementalDataMessage(Vector supplementalData)
		{
			HandshakeMessage message = new HandshakeMessage(this, HandshakeType.supplemental_data);

			writeSupplementalData(message, supplementalData);

			message.writeToRecordStream();
		}

		public virtual byte[] createVerifyData(bool isServer)
		{
			TlsContext context = getContext();
			string asciiLabel = isServer ? ExporterLabel.server_finished : ExporterLabel.client_finished;
			byte[] sslSender = isServer ? TlsUtils.SSL_SERVER : TlsUtils.SSL_CLIENT;
			byte[] hash = getCurrentPRFHash(context, recordStream.getHandshakeHash(), sslSender);
			return TlsUtils.calculateVerifyData(context, asciiLabel, hash);
		}

		/// <summary>
		/// Closes this connection.
		/// </summary>
		/// <exception cref="IOException"> If something goes wrong during closing. </exception>
		public virtual void close()
		{
			handleClose(true);
		}

		public virtual void flush()
		{
			recordStream.flush();
		}

		public virtual bool isClosed()
		{
			return closed;
		}

		public virtual short processMaxFragmentLengthExtension(Hashtable clientExtensions, Hashtable serverExtensions, short alertDescription)
		{
			short maxFragmentLength = TlsExtensionsUtils.getMaxFragmentLengthExtension(serverExtensions);
			if (maxFragmentLength >= 0)
			{
				if (!MaxFragmentLength.isValid(maxFragmentLength) || (!this.resumedSession && maxFragmentLength != TlsExtensionsUtils.getMaxFragmentLengthExtension(clientExtensions)))
				{
					throw new TlsFatalAlert(alertDescription);
				}
			}
			return maxFragmentLength;
		}

		public virtual void refuseRenegotiation()
		{
			/*
			 * RFC 5746 4.5 SSLv3 clients that refuse renegotiation SHOULD use a fatal
			 * handshake_failure alert.
			 */
			if (TlsUtils.isSSL(getContext()))
			{
				throw new TlsFatalAlert(AlertDescription.handshake_failure);
			}

			raiseAlertWarning(AlertDescription.no_renegotiation, "Renegotiation not supported");
		}

		/// <summary>
		/// Make sure the InputStream 'buf' now empty. Fail otherwise.
		/// </summary>
		/// <param name="buf"> The InputStream to check. </param>
		/// <exception cref="IOException"> If 'buf' is not empty. </exception>
		protected internal static void assertEmpty(ByteArrayInputStream buf)
		{
			if (buf.available() > 0)
			{
				throw new TlsFatalAlert(AlertDescription.decode_error);
			}
		}

		protected internal static byte[] createRandomBlock(bool useGMTUnixTime, RandomGenerator randomGenerator)
		{
			byte[] result = new byte[32];
			randomGenerator.nextBytes(result);

			if (useGMTUnixTime)
			{
				TlsUtils.writeGMTUnixTime(result, 0);
			}

			return result;
		}

		protected internal static byte[] createRenegotiationInfo(byte[] renegotiated_connection)
		{
			return TlsUtils.encodeOpaque8(renegotiated_connection);
		}

		protected internal static void establishMasterSecret(TlsContext context, TlsKeyExchange keyExchange)
		{
			byte[] pre_master_secret = keyExchange.generatePremasterSecret();

			try
			{
				context.getSecurityParameters().masterSecret = TlsUtils.calculateMasterSecret(context, pre_master_secret);
			}
			finally
			{
				// TODO Is there a way to ensure the data is really overwritten?
				/*
				 * RFC 2246 8.1. The pre_master_secret should be deleted from memory once the
				 * master_secret has been computed.
				 */
				if (pre_master_secret != null)
				{
					Arrays.fill(pre_master_secret, (byte)0);
				}
			}
		}

		/// <summary>
		/// 'sender' only relevant to SSLv3
		/// </summary>
		protected internal static byte[] getCurrentPRFHash(TlsContext context, TlsHandshakeHash handshakeHash, byte[] sslSender)
		{
			Digest d = handshakeHash.forkPRFHash();

			if (sslSender != null && TlsUtils.isSSL(context))
			{
				d.update(sslSender, 0, sslSender.Length);
			}

			byte[] bs = new byte[d.getDigestSize()];
			d.doFinal(bs, 0);
			return bs;
		}

		protected internal static Hashtable readExtensions(ByteArrayInputStream input)
		{
			if (input.available() < 1)
			{
				return null;
			}

			byte[] extBytes = TlsUtils.readOpaque16(input);

			assertEmpty(input);

			ByteArrayInputStream buf = new ByteArrayInputStream(extBytes);

			// Integer -> byte[]
			Hashtable extensions = new Hashtable();

			while (buf.available() > 0)
			{
				int? extension_type = Integers.valueOf(TlsUtils.readUint16(buf));
				byte[] extension_data = TlsUtils.readOpaque16(buf);

				/*
				 * RFC 3546 2.3 There MUST NOT be more than one extension of the same type.
				 */
				if (null != extensions.put(extension_type, extension_data))
				{
					throw new TlsFatalAlert(AlertDescription.illegal_parameter);
				}
			}

			return extensions;
		}

		protected internal static Vector readSupplementalDataMessage(ByteArrayInputStream input)
		{
			byte[] supp_data = TlsUtils.readOpaque24(input);

			assertEmpty(input);

			ByteArrayInputStream buf = new ByteArrayInputStream(supp_data);

			Vector supplementalData = new Vector();

			while (buf.available() > 0)
			{
				int supp_data_type = TlsUtils.readUint16(buf);
				byte[] data = TlsUtils.readOpaque16(buf);

				supplementalData.addElement(new SupplementalDataEntry(supp_data_type, data));
			}

			return supplementalData;
		}

		protected internal static void writeExtensions(OutputStream output, Hashtable extensions)
		{
			ByteArrayOutputStream buf = new ByteArrayOutputStream();

			/*
			 * NOTE: There are reports of servers that don't accept a zero-length extension as the last
			 * one, so we write out any zero-length ones first as a best-effort workaround.
			 */
			writeSelectedExtensions(buf, extensions, true);
			writeSelectedExtensions(buf, extensions, false);

			byte[] extBytes = buf.toByteArray();

			TlsUtils.writeOpaque16(extBytes, output);
		}

		protected internal static void writeSelectedExtensions(OutputStream output, Hashtable extensions, bool selectEmpty)
		{
			Enumeration keys = extensions.keys();
			while (keys.hasMoreElements())
			{
				int? key = (int?)keys.nextElement();
				int extension_type = key.Value;
				byte[] extension_data = (byte[])extensions.get(key);

				if (selectEmpty == (extension_data.Length == 0))
				{
					TlsUtils.checkUint16(extension_type);
					TlsUtils.writeUint16(extension_type, output);
					TlsUtils.writeOpaque16(extension_data, output);
				}
			}
		}

		protected internal static void writeSupplementalData(OutputStream output, Vector supplementalData)
		{
			ByteArrayOutputStream buf = new ByteArrayOutputStream();

			for (int i = 0; i < supplementalData.size(); ++i)
			{
				SupplementalDataEntry entry = (SupplementalDataEntry)supplementalData.elementAt(i);

				int supp_data_type = entry.getDataType();
				TlsUtils.checkUint16(supp_data_type);
				TlsUtils.writeUint16(supp_data_type, buf);
				TlsUtils.writeOpaque16(entry.getData(), buf);
			}

			byte[] supp_data = buf.toByteArray();

			TlsUtils.writeOpaque24(supp_data, output);
		}

		protected internal static int getPRFAlgorithm(TlsContext context, int ciphersuite)
		{
			bool isTLSv12 = TlsUtils.isTLSv12(context);

			switch (ciphersuite)
			{
			case CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_DH_anon_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA256:
			case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256:
			case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
			case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256:
			case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
			case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256:
			case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
			case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256:
			case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CCM:
			case CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
			case CipherSuite.DRAFT_TLS_DHE_PSK_WITH_AES_128_OCB:
			case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM:
			case CipherSuite.DRAFT_TLS_DHE_PSK_WITH_AES_256_OCB:
			case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.DRAFT_TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
			case CipherSuite.DRAFT_TLS_DHE_RSA_WITH_AES_128_OCB:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8:
			case CipherSuite.DRAFT_TLS_DHE_RSA_WITH_AES_256_OCB:
			case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256:
			case CipherSuite.DRAFT_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
			case CipherSuite.DRAFT_TLS_ECDHE_ECDSA_WITH_AES_128_OCB:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8:
			case CipherSuite.DRAFT_TLS_ECDHE_ECDSA_WITH_AES_256_OCB:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.DRAFT_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
			case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_128_OCB:
			case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_256_OCB:
			case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
			case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
			case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_AES_128_OCB:
			case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_AES_256_OCB:
			case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
			case CipherSuite.TLS_PSK_DHE_WITH_AES_128_CCM_8:
			case CipherSuite.TLS_PSK_DHE_WITH_AES_256_CCM_8:
			case CipherSuite.TLS_PSK_WITH_AES_128_CCM:
			case CipherSuite.TLS_PSK_WITH_AES_128_CCM_8:
			case CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256:
			case CipherSuite.DRAFT_TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:
			case CipherSuite.DRAFT_TLS_PSK_WITH_AES_128_OCB:
			case CipherSuite.TLS_PSK_WITH_AES_256_CCM:
			case CipherSuite.TLS_PSK_WITH_AES_256_CCM_8:
			case CipherSuite.DRAFT_TLS_PSK_WITH_AES_256_OCB:
			case CipherSuite.TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_RSA_PSK_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.DRAFT_TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256:
			case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_RSA_WITH_AES_128_CCM:
			case CipherSuite.TLS_RSA_WITH_AES_128_CCM_8:
			case CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
			case CipherSuite.TLS_RSA_WITH_AES_256_CCM:
			case CipherSuite.TLS_RSA_WITH_AES_256_CCM_8:
			case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256:
			case CipherSuite.TLS_RSA_WITH_NULL_SHA256:
			{
				if (isTLSv12)
				{
					return PRFAlgorithm.tls_prf_sha256;
				}
				throw new TlsFatalAlert(AlertDescription.illegal_parameter);
			}

			case CipherSuite.TLS_DH_anon_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
			case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384:
			case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
			case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384:
			case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_RSA_PSK_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384:
			{
				if (isTLSv12)
				{
					return PRFAlgorithm.tls_prf_sha384;
				}
				throw new TlsFatalAlert(AlertDescription.illegal_parameter);
			}

			case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA384:
			case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:
			case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA384:
			case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384:
			case CipherSuite.TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:
			case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA384:
			case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA384:
			case CipherSuite.TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384:
			case CipherSuite.TLS_PSK_WITH_NULL_SHA384:
			case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA384:
			case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384:
			case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA384:
			{
				if (isTLSv12)
				{
					return PRFAlgorithm.tls_prf_sha384;
				}
				return PRFAlgorithm.tls_prf_legacy;
			}

			default:
			{
				if (isTLSv12)
				{
					return PRFAlgorithm.tls_prf_sha256;
				}
				return PRFAlgorithm.tls_prf_legacy;
			}
			}
		}

		public class HandshakeMessage : ByteArrayOutputStream
		{
			private readonly TlsProtocol outerInstance;

			public HandshakeMessage(TlsProtocol outerInstance, short handshakeType) : this(outerInstance, handshakeType, 60)
			{
				this.outerInstance = outerInstance;
			}

			public HandshakeMessage(TlsProtocol outerInstance, short handshakeType, int length) : base(length + 4)
			{
				this.outerInstance = outerInstance;
				TlsUtils.writeUint8(handshakeType, this);
                // Reserve space for length
			    TlsUtils.writeUint24(0, this);
                //count += 3;
			}

			public virtual void writeToRecordStream()
			{
				// Patch actual length back in
				int length = count() - 4;
				TlsUtils.checkUint24(length);
				TlsUtils.writeUint24(length, buf, 1);
				outerInstance.writeHandshakeMessage(buf, 0, count());
				//PORT: buf = null;
			}
		}
	}

}
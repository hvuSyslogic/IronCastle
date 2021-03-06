﻿using System.IO;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.util.io;

namespace org.bouncycastle.crypto.tls
{

	
	/// <summary>
	/// An implementation of the TLS 1.0/1.1/1.2 record layer, allowing downgrade to SSLv3.
	/// </summary>
	public class RecordStream
	{
		private static int DEFAULT_PLAINTEXT_LIMIT = (1 << 14);
		internal const int TLS_HEADER_SIZE = 5;
		internal const int TLS_HEADER_TYPE_OFFSET = 0;
		internal const int TLS_HEADER_VERSION_OFFSET = 1;
		internal const int TLS_HEADER_LENGTH_OFFSET = 3;

		private TlsProtocol handler;
		private InputStream input;
		private OutputStream output;
		private TlsCompression pendingCompression = null, readCompression = null, writeCompression = null;
		private TlsCipher pendingCipher = null, readCipher = null, writeCipher = null;
		private SequenceNumber readSeqNo = new SequenceNumber(), writeSeqNo = new SequenceNumber();
		private ByteArrayOutputStream buffer = new ByteArrayOutputStream();

		private TlsHandshakeHash handshakeHash = null;
		private SimpleOutputStream handshakeHashUpdater ;

		public class SimpleOutputStreamAnonymousInnerClass : SimpleOutputStream
		{
		    private readonly RecordStream _outerInstance;

		    public SimpleOutputStreamAnonymousInnerClass(RecordStream outerInstance)
		    {
		        _outerInstance = outerInstance;
		    }

            public override void write(byte[] buf, int off, int len)
			{
			    _outerInstance.handshakeHash.update(buf, off, len);
			}
		}

		private ProtocolVersion readVersion = null, writeVersion = null;
		private bool restrictReadVersion = true;

		private int plaintextLimit, compressedLimit, ciphertextLimit;

		public RecordStream(TlsProtocol handler, InputStream input, OutputStream output)
		{
			this.handler = handler;
			this.input = input;
			this.output = output;
			this.readCompression = new TlsNullCompression();
			this.writeCompression = this.readCompression;
		    handshakeHashUpdater = new SimpleOutputStreamAnonymousInnerClass(this);
        }

		public virtual void init(TlsContext context)
		{
			this.readCipher = new TlsNullCipher(context);
			this.writeCipher = this.readCipher;
			this.handshakeHash = new DeferredHash();
			this.handshakeHash.init(context);

			setPlaintextLimit(DEFAULT_PLAINTEXT_LIMIT);
		}

		public virtual int getPlaintextLimit()
		{
			return plaintextLimit;
		}

		public virtual void setPlaintextLimit(int plaintextLimit)
		{
			this.plaintextLimit = plaintextLimit;
			this.compressedLimit = this.plaintextLimit + 1024;
			this.ciphertextLimit = this.compressedLimit + 1024;
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

		/// <summary>
		/// RFC 5246 E.1. "Earlier versions of the TLS specification were not fully clear on what the
		/// record layer version number (TLSPlaintext.version) should contain when sending ClientHello
		/// (i.e., before it is known which version of the protocol will be employed). Thus, TLS servers
		/// compliant with this specification MUST accept any value {03,XX} as the record layer version
		/// number for ClientHello."
		/// </summary>
		public virtual void setRestrictReadVersion(bool enabled)
		{
			this.restrictReadVersion = enabled;
		}

		public virtual void setPendingConnectionState(TlsCompression tlsCompression, TlsCipher tlsCipher)
		{
			this.pendingCompression = tlsCompression;
			this.pendingCipher = tlsCipher;
		}

		public virtual void sentWriteCipherSpec()
		{
			if (pendingCompression == null || pendingCipher == null)
			{
				throw new TlsFatalAlert(AlertDescription.handshake_failure);
			}
			this.writeCompression = this.pendingCompression;
			this.writeCipher = this.pendingCipher;
			this.writeSeqNo = new SequenceNumber();
		}

		public virtual void receivedReadCipherSpec()
		{
			if (pendingCompression == null || pendingCipher == null)
			{
				throw new TlsFatalAlert(AlertDescription.handshake_failure);
			}
			this.readCompression = this.pendingCompression;
			this.readCipher = this.pendingCipher;
			this.readSeqNo = new SequenceNumber();
		}

		public virtual void finaliseHandshake()
		{
			if (readCompression != pendingCompression || writeCompression != pendingCompression || readCipher != pendingCipher || writeCipher != pendingCipher)
			{
				throw new TlsFatalAlert(AlertDescription.handshake_failure);
			}
			this.pendingCompression = null;
			this.pendingCipher = null;
		}

		public virtual void checkRecordHeader(byte[] recordHeader)
		{
			short type = TlsUtils.readUint8(recordHeader, TLS_HEADER_TYPE_OFFSET);

			/*
			 * RFC 5246 6. If a TLS implementation receives an unexpected record type, it MUST send an
			 * unexpected_message alert.
			 */
			checkType(type, AlertDescription.unexpected_message);

			if (!restrictReadVersion)
			{
				int version = TlsUtils.readVersionRaw(recordHeader, TLS_HEADER_VERSION_OFFSET);
				if ((version & 0xffffff00) != 0x0300)
				{
					throw new TlsFatalAlert(AlertDescription.illegal_parameter);
				}
			}
			else
			{
				ProtocolVersion version = TlsUtils.readVersion(recordHeader, TLS_HEADER_VERSION_OFFSET);
				if (readVersion == null)
				{
					// Will be set later in 'readRecord'
				}
				else if (!version.Equals(readVersion))
				{
					throw new TlsFatalAlert(AlertDescription.illegal_parameter);
				}
			}

			int length = TlsUtils.readUint16(recordHeader, TLS_HEADER_LENGTH_OFFSET);

			checkLength(length, ciphertextLimit, AlertDescription.record_overflow);
		}

		public virtual bool readRecord()
		{
			byte[] recordHeader = TlsUtils.readAllOrNothing(TLS_HEADER_SIZE, input);
			if (recordHeader == null)
			{
				return false;
			}

			short type = TlsUtils.readUint8(recordHeader, TLS_HEADER_TYPE_OFFSET);

			/*
			 * RFC 5246 6. If a TLS implementation receives an unexpected record type, it MUST send an
			 * unexpected_message alert.
			 */
			checkType(type, AlertDescription.unexpected_message);

			if (!restrictReadVersion)
			{
				int version = TlsUtils.readVersionRaw(recordHeader, TLS_HEADER_VERSION_OFFSET);
				if ((version & 0xffffff00) != 0x0300)
				{
					throw new TlsFatalAlert(AlertDescription.illegal_parameter);
				}
			}
			else
			{
				ProtocolVersion version = TlsUtils.readVersion(recordHeader, TLS_HEADER_VERSION_OFFSET);
				if (readVersion == null)
				{
					readVersion = version;
				}
				else if (!version.Equals(readVersion))
				{
					throw new TlsFatalAlert(AlertDescription.illegal_parameter);
				}
			}

			int length = TlsUtils.readUint16(recordHeader, TLS_HEADER_LENGTH_OFFSET);

			checkLength(length, ciphertextLimit, AlertDescription.record_overflow);

			byte[] plaintext = decodeAndVerify(type, input, length);
			handler.processRecord(type, plaintext, 0, plaintext.Length);
			return true;
		}

		public virtual byte[] decodeAndVerify(short type, InputStream input, int len)
		{
			byte[] buf = TlsUtils.readFully(len, input);

			long seqNo = readSeqNo.nextValue(AlertDescription.unexpected_message);
			byte[] decoded = readCipher.decodeCiphertext(seqNo, type, buf, 0, buf.Length);

			checkLength(decoded.Length, compressedLimit, AlertDescription.record_overflow);

			/*
			 * TODO RFC 5246 6.2.2. Implementation note: Decompression functions are responsible for
			 * ensuring that messages cannot cause internal buffer overflows.
			 */
			OutputStream cOut = readCompression.decompress(buffer);
			if (cOut != buffer)
			{
				cOut.write(decoded, 0, decoded.Length);
				cOut.flush();
				decoded = getBufferContents();
			}

			/*
			 * RFC 5246 6.2.2. If the decompression function encounters a TLSCompressed.fragment that
			 * would decompress to a length in excess of 2^14 bytes, it should report a fatal
			 * decompression failure error.
			 */
			checkLength(decoded.Length, plaintextLimit, AlertDescription.decompression_failure);

			/*
			 * RFC 5246 6.2.1 Implementations MUST NOT send zero-length fragments of Handshake, Alert,
			 * or ChangeCipherSpec content types.
			 */
			if (decoded.Length < 1 && type != ContentType.application_data)
			{
				throw new TlsFatalAlert(AlertDescription.illegal_parameter);
			}

			return decoded;
		}

		public virtual void writeRecord(short type, byte[] plaintext, int plaintextOffset, int plaintextLength)
		{
			// Never send anything until a valid ClientHello has been received
			if (writeVersion == null)
			{
				return;
			}

			/*
			 * RFC 5246 6. Implementations MUST NOT send record types not defined in this document
			 * unless negotiated by some extension.
			 */
			checkType(type, AlertDescription.internal_error);

			/*
			 * RFC 5246 6.2.1 The length should not exceed 2^14.
			 */
			checkLength(plaintextLength, plaintextLimit, AlertDescription.internal_error);

			/*
			 * RFC 5246 6.2.1 Implementations MUST NOT send zero-length fragments of Handshake, Alert,
			 * or ChangeCipherSpec content types.
			 */
			if (plaintextLength < 1 && type != ContentType.application_data)
			{
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}

			OutputStream cOut = writeCompression.compress(buffer);

			long seqNo = writeSeqNo.nextValue(AlertDescription.internal_error);

			byte[] ciphertext;
			if (cOut == buffer)
			{
				ciphertext = writeCipher.encodePlaintext(seqNo, type, plaintext, plaintextOffset, plaintextLength);
			}
			else
			{
				cOut.write(plaintext, plaintextOffset, plaintextLength);
				cOut.flush();
				byte[] compressed = getBufferContents();

				/*
				 * RFC 5246 6.2.2. Compression must be lossless and may not increase the content length
				 * by more than 1024 bytes.
				 */
				checkLength(compressed.Length, plaintextLength + 1024, AlertDescription.internal_error);

				ciphertext = writeCipher.encodePlaintext(seqNo, type, compressed, 0, compressed.Length);
			}

			/*
			 * RFC 5246 6.2.3. The length may not exceed 2^14 + 2048.
			 */
			checkLength(ciphertext.Length, ciphertextLimit, AlertDescription.internal_error);

			byte[] record = new byte[ciphertext.Length + TLS_HEADER_SIZE];
			TlsUtils.writeUint8(type, record, TLS_HEADER_TYPE_OFFSET);
			TlsUtils.writeVersion(writeVersion, record, TLS_HEADER_VERSION_OFFSET);
			TlsUtils.writeUint16(ciphertext.Length, record, TLS_HEADER_LENGTH_OFFSET);
			JavaSystem.arraycopy(ciphertext, 0, record, TLS_HEADER_SIZE, ciphertext.Length);
			output.write(record);
			output.flush();
		}

		public virtual void notifyHelloComplete()
		{
			this.handshakeHash = handshakeHash.notifyPRFDetermined();
		}

		public virtual TlsHandshakeHash getHandshakeHash()
		{
			return handshakeHash;
		}

		public virtual OutputStream getHandshakeHashUpdater()
		{
			return handshakeHashUpdater;
		}

		public virtual TlsHandshakeHash prepareToFinish()
		{
			TlsHandshakeHash result = handshakeHash;
			this.handshakeHash = handshakeHash.stopTracking();
			return result;
		}

		public virtual void safeClose()
		{
			try
			{
				input.close();
			}
			catch (IOException)
			{
			}

			try
			{
				output.close();
			}
			catch (IOException)
			{
			}
		}

		public virtual void flush()
		{
			output.flush();
		}

		private byte[] getBufferContents()
		{
			byte[] contents = buffer.toByteArray();
			buffer.reset();
			return contents;
		}

		private static void checkType(short type, short alertDescription)
		{
			switch (type)
			{
			case ContentType.application_data:
			case ContentType.alert:
			case ContentType.change_cipher_spec:
			case ContentType.handshake:
	//        case ContentType.heartbeat:
				break;
			default:
				throw new TlsFatalAlert(alertDescription);
			}
		}

		private static void checkLength(int length, int limit, short alertDescription)
		{
			if (length > limit)
			{
				throw new TlsFatalAlert(alertDescription);
			}
		}

		public class SequenceNumber
		{
			internal long value = 0L;
			internal bool exhausted = false;

			public virtual long nextValue(short alertDescription)
			{
				lock (this)
				{
					if (exhausted)
					{
						throw new TlsFatalAlert(alertDescription);
					}
					long result = value;
					if (++value == 0)
					{
						exhausted = true;
					}
					return result;
				}
			}
		}
	}

}
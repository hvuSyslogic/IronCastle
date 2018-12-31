using System.IO;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;
using org.bouncycastle.util.io;

namespace org.bouncycastle.crypto.tls
{

		
	public class HeartbeatMessage
	{
		protected internal short type;
		protected internal byte[] payload;
		protected internal int paddingLength;

		public HeartbeatMessage(short type, byte[] payload, int paddingLength)
		{
			if (!HeartbeatMessageType.isValid(type))
			{
				throw new IllegalArgumentException("'type' is not a valid HeartbeatMessageType value");
			}
			if (payload == null || payload.Length >= (1 << 16))
			{
				throw new IllegalArgumentException("'payload' must have length < 2^16");
			}
			if (paddingLength < 16)
			{
				throw new IllegalArgumentException("'paddingLength' must be at least 16");
			}

			this.type = type;
			this.payload = payload;
			this.paddingLength = paddingLength;
		}

		/// <summary>
		/// Encode this <seealso cref="HeartbeatMessage"/> to an <seealso cref="OutputStream"/>.
		/// </summary>
		/// <param name="output">
		///            the <seealso cref="OutputStream"/> to encode to. </param>
		/// <exception cref="IOException"> </exception>
		public virtual void encode(TlsContext context, OutputStream output)
		{
			TlsUtils.writeUint8(type, output);

			TlsUtils.checkUint16(payload.Length);
			TlsUtils.writeUint16(payload.Length, output);
			output.write(payload);

			byte[] padding = new byte[paddingLength];
			context.getNonceRandomGenerator().nextBytes(padding);
			output.write(padding);
		}

		/// <summary>
		/// Parse a <seealso cref="HeartbeatMessage"/> from an <seealso cref="InputStream"/>.
		/// </summary>
		/// <param name="input">
		///            the <seealso cref="InputStream"/> to parse from. </param>
		/// <returns> a <seealso cref="HeartbeatMessage"/> object. </returns>
		/// <exception cref="IOException"> </exception>
		public static HeartbeatMessage parse(InputStream input)
		{
			short type = TlsUtils.readUint8(input);
			if (!HeartbeatMessageType.isValid(type))
			{
				throw new TlsFatalAlert(AlertDescription.illegal_parameter);
			}

			int payload_length = TlsUtils.readUint16(input);

			PayloadBuffer buf = new PayloadBuffer();
			Streams.pipeAll(input, buf);

			byte[] payload = buf.toTruncatedByteArray(payload_length);
			if (payload == null)
			{
				/*
				 * RFC 6520 4. If the payload_length of a received HeartbeatMessage is too large, the
				 * received HeartbeatMessage MUST be discarded silently.
				 */
				return null;
			}

			int padding_length = buf.size() - payload.Length;

			/*
			 * RFC 6520 4. The padding of a received HeartbeatMessage message MUST be ignored
			 */
			return new HeartbeatMessage(type, payload, padding_length);
		}

		public class PayloadBuffer : ByteArrayOutputStream
		{
			public virtual byte[] toTruncatedByteArray(int payloadLength)
			{
				/*
				 * RFC 6520 4. The padding_length MUST be at least 16.
				 */
				int minimumCount = payloadLength + 16;
				if (count() < minimumCount)
				{
					return null;
				}
				return Arrays.copyOf(buf, payloadLength);
			}
		}
	}

}
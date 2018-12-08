using System.IO;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.tls
{

	public class HeartbeatExtension
	{
		protected internal short mode;

		public HeartbeatExtension(short mode)
		{
			if (!HeartbeatMode.isValid(mode))
			{
				throw new IllegalArgumentException("'mode' is not a valid HeartbeatMode value");
			}

			this.mode = mode;
		}

		public virtual short getMode()
		{
			return mode;
		}

		/// <summary>
		/// Encode this <seealso cref="HeartbeatExtension"/> to an <seealso cref="OutputStream"/>.
		/// </summary>
		/// <param name="output">
		///            the <seealso cref="OutputStream"/> to encode to. </param>
		/// <exception cref="IOException"> </exception>
		public virtual void encode(OutputStream output)
		{
			TlsUtils.writeUint8(mode, output);
		}

		/// <summary>
		/// Parse a <seealso cref="HeartbeatExtension"/> from an <seealso cref="InputStream"/>.
		/// </summary>
		/// <param name="input">
		///            the <seealso cref="InputStream"/> to parse from. </param>
		/// <returns> a <seealso cref="HeartbeatExtension"/> object. </returns>
		/// <exception cref="IOException"> </exception>
		public static HeartbeatExtension parse(InputStream input)
		{
			short mode = TlsUtils.readUint8(input);
			if (!HeartbeatMode.isValid(mode))
			{
				throw new TlsFatalAlert(AlertDescription.illegal_parameter);
			}

			return new HeartbeatExtension(mode);
		}
	}

}
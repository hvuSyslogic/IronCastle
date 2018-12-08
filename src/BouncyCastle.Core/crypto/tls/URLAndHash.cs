using System.IO;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.tls
{

	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// RFC 6066 5.
	/// </summary>
	public class URLAndHash
	{
		protected internal string url;
		protected internal byte[] sha1Hash;

		public URLAndHash(string url, byte[] sha1Hash)
		{
			if (string.ReferenceEquals(url, null) || url.Length < 1 || url.Length >= (1 << 16))
			{
				throw new IllegalArgumentException("'url' must have length from 1 to (2^16 - 1)");
			}
			if (sha1Hash != null && sha1Hash.Length != 20)
			{
				throw new IllegalArgumentException("'sha1Hash' must have length == 20, if present");
			}

			this.url = url;
			this.sha1Hash = sha1Hash;
		}

		public virtual string getURL()
		{
			return url;
		}

		public virtual byte[] getSHA1Hash()
		{
			return sha1Hash;
		}

		/// <summary>
		/// Encode this <seealso cref="URLAndHash"/> to an <seealso cref="OutputStream"/>.
		/// </summary>
		/// <param name="output"> the <seealso cref="OutputStream"/> to encode to. </param>
		/// <exception cref="IOException"> </exception>
		public virtual void encode(OutputStream output)
		{
			byte[] urlEncoding = Strings.toByteArray(this.url);
			TlsUtils.writeOpaque16(urlEncoding, output);

			if (this.sha1Hash == null)
			{
				TlsUtils.writeUint8(0, output);
			}
			else
			{
				TlsUtils.writeUint8(1, output);
				output.write(this.sha1Hash);
			}
		}

		/// <summary>
		/// Parse a <seealso cref="URLAndHash"/> from an <seealso cref="InputStream"/>.
		/// </summary>
		/// <param name="context">
		///            the <seealso cref="TlsContext"/> of the current connection. </param>
		/// <param name="input">
		///            the <seealso cref="InputStream"/> to parse from. </param>
		/// <returns> a <seealso cref="URLAndHash"/> object. </returns>
		/// <exception cref="IOException"> </exception>
		public static URLAndHash parse(TlsContext context, InputStream input)
		{
			byte[] urlEncoding = TlsUtils.readOpaque16(input);
			if (urlEncoding.Length < 1)
			{
				throw new TlsFatalAlert(AlertDescription.illegal_parameter);
			}
			string url = Strings.fromByteArray(urlEncoding);

			byte[] sha1Hash = null;
			short padding = TlsUtils.readUint8(input);
			switch (padding)
			{
			case 0:
				if (TlsUtils.isTLSv12(context))
				{
					throw new TlsFatalAlert(AlertDescription.illegal_parameter);
				}
				break;
			case 1:
				sha1Hash = TlsUtils.readFully(20, input);
				break;
			default:
				throw new TlsFatalAlert(AlertDescription.illegal_parameter);
			}

			return new URLAndHash(url, sha1Hash);
		}
	}

}
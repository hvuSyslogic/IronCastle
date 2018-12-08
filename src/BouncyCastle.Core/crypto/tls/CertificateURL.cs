using System.IO;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.crypto.tls
{

	/*
	 * RFC 3546 3.3
	 */
	public class CertificateURL
	{
		protected internal short type;
		protected internal Vector urlAndHashList;

		/// <param name="type">
		///            see <seealso cref="CertChainType"/> for valid constants. </param>
		/// <param name="urlAndHashList">
		///            a <seealso cref="Vector"/> of <seealso cref="URLAndHash"/>. </param>
		public CertificateURL(short type, Vector urlAndHashList)
		{
			if (!CertChainType.isValid(type))
			{
				throw new IllegalArgumentException("'type' is not a valid CertChainType value");
			}
			if (urlAndHashList == null || urlAndHashList.isEmpty())
			{
				throw new IllegalArgumentException("'urlAndHashList' must have length > 0");
			}

			this.type = type;
			this.urlAndHashList = urlAndHashList;
		}

		/// <returns> <seealso cref="CertChainType"/> </returns>
		public virtual short getType()
		{
			return type;
		}

		/// <returns> a <seealso cref="Vector"/> of <seealso cref="URLAndHash"/>  </returns>
		public virtual Vector getURLAndHashList()
		{
			return urlAndHashList;
		}

		/// <summary>
		/// Encode this <seealso cref="CertificateURL"/> to an <seealso cref="OutputStream"/>.
		/// </summary>
		/// <param name="output"> the <seealso cref="OutputStream"/> to encode to. </param>
		/// <exception cref="IOException"> </exception>
		public virtual void encode(OutputStream output)
		{
			TlsUtils.writeUint8(this.type, output);

			ListBuffer16 buf = new ListBuffer16(this);
			for (int i = 0; i < this.urlAndHashList.size(); ++i)
			{
				URLAndHash urlAndHash = (URLAndHash)this.urlAndHashList.elementAt(i);
				urlAndHash.encode(buf);
			}
			buf.encodeTo(output);
		}

		/// <summary>
		/// Parse a <seealso cref="CertificateURL"/> from an <seealso cref="InputStream"/>.
		/// </summary>
		/// <param name="context">
		///            the <seealso cref="TlsContext"/> of the current connection. </param>
		/// <param name="input">
		///            the <seealso cref="InputStream"/> to parse from. </param>
		/// <returns> a <seealso cref="CertificateURL"/> object. </returns>
		/// <exception cref="IOException"> </exception>
		public static CertificateURL parse(TlsContext context, InputStream input)
		{
			short type = TlsUtils.readUint8(input);
			if (!CertChainType.isValid(type))
			{
				throw new TlsFatalAlert(AlertDescription.decode_error);
			}

			int totalLength = TlsUtils.readUint16(input);
			if (totalLength < 1)
			{
				throw new TlsFatalAlert(AlertDescription.decode_error);
			}

			byte[] urlAndHashListData = TlsUtils.readFully(totalLength, input);

			ByteArrayInputStream buf = new ByteArrayInputStream(urlAndHashListData);

			Vector url_and_hash_list = new Vector();
			while (buf.available() > 0)
			{
				URLAndHash url_and_hash = URLAndHash.parse(context, buf);
				url_and_hash_list.addElement(url_and_hash);
			}

			return new CertificateURL(type, url_and_hash_list);
		}

		// TODO Could be more generally useful
		public class ListBuffer16 : ByteArrayOutputStream
		{
			private readonly CertificateURL outerInstance;

			public ListBuffer16(CertificateURL outerInstance)
			{
				this.outerInstance = outerInstance;
				// Reserve space for length
				TlsUtils.writeUint16(0, this);
			}

			public virtual void encodeTo(OutputStream output)
			{
				// Patch actual length back in
				int length = count() - 2;
				TlsUtils.checkUint16(length);
				TlsUtils.writeUint16(length, buf, 0);
				output.write(buf, 0, count());
				buf = null;
			}
		}
	}

}
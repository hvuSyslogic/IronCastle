using System.IO;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.crypto.tls
{

	using Arrays = org.bouncycastle.util.Arrays;
	using Streams = org.bouncycastle.util.io.Streams;

	public class ServerNameList
	{
		protected internal Vector serverNameList;

		/// <param name="serverNameList"> a <seealso cref="Vector"/> of <seealso cref="ServerName"/>. </param>
		public ServerNameList(Vector serverNameList)
		{
			if (serverNameList == null)
			{
				throw new IllegalArgumentException("'serverNameList' must not be null");
			}

			this.serverNameList = serverNameList;
		}

		/// <returns> a <seealso cref="Vector"/> of <seealso cref="ServerName"/>. </returns>
		public virtual Vector getServerNameList()
		{
			return serverNameList;
		}

		/// <summary>
		/// Encode this <seealso cref="ServerNameList"/> to an <seealso cref="OutputStream"/>.
		/// </summary>
		/// <param name="output">
		///            the <seealso cref="OutputStream"/> to encode to. </param>
		/// <exception cref="IOException"> </exception>
		public virtual void encode(OutputStream output)
		{
			ByteArrayOutputStream buf = new ByteArrayOutputStream();

			short[] nameTypesSeen = new short[0];
			for (int i = 0; i < serverNameList.size(); ++i)
			{
				ServerName entry = (ServerName)serverNameList.elementAt(i);

				nameTypesSeen = checkNameType(nameTypesSeen, entry.getNameType());
				if (nameTypesSeen == null)
				{
					throw new TlsFatalAlert(AlertDescription.internal_error);
				}

				entry.encode(buf);
			}

			TlsUtils.checkUint16(buf.size());
			TlsUtils.writeUint16(buf.size(), output);
			Streams.writeBufTo(buf, output);
		}

		/// <summary>
		/// Parse a <seealso cref="ServerNameList"/> from an <seealso cref="InputStream"/>.
		/// </summary>
		/// <param name="input">
		///            the <seealso cref="InputStream"/> to parse from. </param>
		/// <returns> a <seealso cref="ServerNameList"/> object. </returns>
		/// <exception cref="IOException"> </exception>
		public static ServerNameList parse(InputStream input)
		{
			int length = TlsUtils.readUint16(input);
			if (length < 1)
			{
				throw new TlsFatalAlert(AlertDescription.decode_error);
			}

			byte[] data = TlsUtils.readFully(length, input);

			ByteArrayInputStream buf = new ByteArrayInputStream(data);

			short[] nameTypesSeen = new short[0];
			Vector server_name_list = new Vector();
			while (buf.available() > 0)
			{
				ServerName entry = ServerName.parse(buf);

				nameTypesSeen = checkNameType(nameTypesSeen, entry.getNameType());
				if (nameTypesSeen == null)
				{
					throw new TlsFatalAlert(AlertDescription.illegal_parameter);
				}

				server_name_list.addElement(entry);
			}

			return new ServerNameList(server_name_list);
		}

		private static short[] checkNameType(short[] nameTypesSeen, short nameType)
		{
			/*
			 * RFC 6066 3. The ServerNameList MUST NOT contain more than one name of the same
			 * name_type.
			 */
			if (!NameType.isValid(nameType) || Arrays.contains(nameTypesSeen, nameType))
			{
				return null;
			}
			return Arrays.append(nameTypesSeen, nameType);
		}
	}

}
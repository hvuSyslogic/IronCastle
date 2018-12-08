using System.IO;
using System.Text;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.tls
{

	public class ServerName
	{
		protected internal short nameType;
		protected internal object name;

		public ServerName(short nameType, object name)
		{
			if (!isCorrectType(nameType, name))
			{
				throw new IllegalArgumentException("'name' is not an instance of the correct type");
			}

			this.nameType = nameType;
			this.name = name;
		}

		public virtual short getNameType()
		{
			return nameType;
		}

		public virtual object getName()
		{
			return name;
		}

		public virtual string getHostName()
		{
			if (!isCorrectType(NameType.host_name, name))
			{
				throw new IllegalStateException("'name' is not a HostName string");
			}
			return (string)name;
		}

		/// <summary>
		/// Encode this <seealso cref="ServerName"/> to an <seealso cref="OutputStream"/>.
		/// </summary>
		/// <param name="output">
		///            the <seealso cref="OutputStream"/> to encode to. </param>
		/// <exception cref="IOException"> </exception>
		public virtual void encode(OutputStream output)
		{
			TlsUtils.writeUint8(nameType, output);

			switch (nameType)
			{
			case NameType.host_name:
				byte[] asciiEncoding = ((string)name).GetBytes(Encoding.ASCII);
				if (asciiEncoding.Length < 1)
				{
					throw new TlsFatalAlert(AlertDescription.internal_error);
				}
				TlsUtils.writeOpaque16(asciiEncoding, output);
				break;
			default:
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}
		}

		/// <summary>
		/// Parse a <seealso cref="ServerName"/> from an <seealso cref="InputStream"/>.
		/// </summary>
		/// <param name="input">
		///            the <seealso cref="InputStream"/> to parse from. </param>
		/// <returns> a <seealso cref="ServerName"/> object. </returns>
		/// <exception cref="IOException"> </exception>
		public static ServerName parse(InputStream input)
		{
			short name_type = TlsUtils.readUint8(input);
			object name;

			switch (name_type)
			{
			case NameType.host_name:
			{
				byte[] asciiEncoding = TlsUtils.readOpaque16(input);
				if (asciiEncoding.Length < 1)
				{
					throw new TlsFatalAlert(AlertDescription.decode_error);
				}
				name = StringHelper.NewString(asciiEncoding, "ASCII");
				break;
			}
			default:
				throw new TlsFatalAlert(AlertDescription.decode_error);
			}

			return new ServerName(name_type, name);
		}

		protected internal static bool isCorrectType(short nameType, object name)
		{
			switch (nameType)
			{
			case NameType.host_name:
				return name is string;
			default:
				throw new IllegalArgumentException("'nameType' is an unsupported NameType");
			}
		}
	}

}
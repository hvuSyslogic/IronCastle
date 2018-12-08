using System;

namespace org.bouncycastle.openpgp
{

	using BCPGInputStream = org.bouncycastle.bcpg.BCPGInputStream;
	using LiteralDataPacket = org.bouncycastle.bcpg.LiteralDataPacket;

	/// <summary>
	/// A single literal data packet in a PGP object stream.
	/// </summary>
	public class PGPLiteralData
	{
		/// <summary>
		/// Format tag for binary literal data </summary>
		public const char BINARY = 'b';
		/// <summary>
		/// Format tag for textual literal data </summary>
		public const char TEXT = 't';
		/// <summary>
		/// Format tag for UTF-8 encoded textual literal data </summary>
		public const char UTF8 = 'u';

		/// <summary>
		/// The special name indicating a "for your eyes only" packet.
		/// </summary>
		public const string CONSOLE = "_CONSOLE";

		/// <summary>
		/// The special time for a modification time of "now" or
		/// the present time.
		/// </summary>
		public static readonly DateTime NOW = new DateTime(0L);

		internal LiteralDataPacket data;

		public PGPLiteralData(BCPGInputStream pIn)
		{
			data = (LiteralDataPacket)pIn.readPacket();
		}

		/// <summary>
		/// Return the format of the data packet. One of <seealso cref="#BINARY"/>, <seealso cref="#TEXT"/> or <seealso cref="#UTF8"/>
		/// </summary>
		public virtual int getFormat()
		{
			return data.getFormat();
		}

		/// <summary>
		/// Return the file name associated with the data packet.
		/// </summary>
		public virtual string getFileName()
		{
			return data.getFileName();
		}

		/// <summary>
		/// Return the file name as an uninterpreted (UTF-8 encoded) byte array.
		/// </summary>
		public virtual byte[] getRawFileName()
		{
			return data.getRawFileName();
		}

		/// <summary>
		/// Return the modification time for the file (at second level precision).
		/// </summary>
		public virtual DateTime getModificationTime()
		{
			return new DateTime(data.getModificationTime());
		}

		/// <summary>
		/// Return the raw input stream for the data packet.
		/// </summary>
		public virtual InputStream getInputStream()
		{
			return data.getInputStream();
		}

		/// <summary>
		/// Return the input stream representing the data stream.
		/// Equivalent to <seealso cref="#getInputStream()"/>.
		/// </summary>
		public virtual InputStream getDataStream()
		{
			return this.getInputStream();
		}
	}

}
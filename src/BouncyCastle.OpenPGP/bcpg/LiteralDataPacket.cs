namespace org.bouncycastle.bcpg
{

	using Arrays = org.bouncycastle.util.Arrays;
	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// Generic literal data packet.
	/// </summary>
	public class LiteralDataPacket : InputStreamPacket
	{
		internal int format;
		internal byte[] fileName;
		internal long modDate;

		public LiteralDataPacket(BCPGInputStream @in) : base(@in)
		{

			format = @in.read();
			int l = @in.read();

			fileName = new byte[l];
			for (int i = 0; i != fileName.Length; i++)
			{
				int ch = @in.read();
				if (ch < 0)
				{
					throw new IOException("literal data truncated in header");
				}
				fileName[i] = (byte)ch;
			}

			modDate = ((long)@in.read() << 24) | (@in.read() << 16) | (@in.read() << 8) | @in.read();
			if (modDate < 0)
			{
				throw new IOException("literal data truncated in header");
			}
		}

		/// <summary>
		/// Return the format tag of the data packet.
		/// </summary>
		public virtual int getFormat()
		{
			return format;
		}

		/// <summary>
		/// Return the modification time for the file (milliseconds at second level precision).
		/// </summary>
		public virtual long getModificationTime()
		{
			return modDate * 1000L;
		}

		/// <summary>
		/// Return the file name associated with the data packet.
		/// </summary>
		public virtual string getFileName()
		{
			return Strings.fromUTF8ByteArray(fileName);
		}

		/// <summary>
		/// Return the file name as an uninterpreted byte array.
		/// </summary>
		public virtual byte[] getRawFileName()
		{
			return Arrays.clone(fileName);
		}
	}

}
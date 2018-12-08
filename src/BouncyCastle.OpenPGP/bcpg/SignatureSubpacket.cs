namespace org.bouncycastle.bcpg
{

	/// <summary>
	/// Basic type for a PGP Signature sub-packet.
	/// </summary>
	public class SignatureSubpacket
	{
		internal int type;
		internal bool critical;
//JAVA TO C# CONVERTER NOTE: Fields cannot have the same name as methods:
		internal bool isLongLength_Renamed;
		protected internal byte[] data;

		public SignatureSubpacket(int type, bool critical, bool isLongLength, byte[] data)
		{
			this.type = type;
			this.critical = critical;
			this.isLongLength_Renamed = isLongLength;
			this.data = data;
		}

		public virtual int getType()
		{
			return type;
		}

		public virtual bool isCritical()
		{
			return critical;
		}

		public virtual bool isLongLength()
		{
			return isLongLength_Renamed;
		}

		/// <summary>
		/// return the generic data making up the packet.
		/// </summary>
		public virtual byte[] getData()
		{
			return data;
		}

		public virtual void encode(OutputStream @out)
		{
			int bodyLen = data.Length + 1;

			if (isLongLength_Renamed)
			{
				@out.write(0xff);
				@out.write((byte)(bodyLen >> 24));
				@out.write((byte)(bodyLen >> 16));
				@out.write((byte)(bodyLen >> 8));
				@out.write((byte)bodyLen);
			}
			else
			{
				if (bodyLen < 192)
				{
					@out.write((byte)bodyLen);
				}
				else if (bodyLen <= 8383)
				{
					bodyLen -= 192;

					@out.write(unchecked((byte)(((bodyLen >> 8) & 0xff) + 192)));
					@out.write((byte)bodyLen);
				}
				else
				{
					@out.write(0xff);
					@out.write((byte)(bodyLen >> 24));
					@out.write((byte)(bodyLen >> 16));
					@out.write((byte)(bodyLen >> 8));
					@out.write((byte)bodyLen);
				}
			}

			if (critical)
			{
				@out.write(0x80 | type);
			}
			else
			{
				@out.write(type);
			}

			@out.write(data);
		}
	}

}
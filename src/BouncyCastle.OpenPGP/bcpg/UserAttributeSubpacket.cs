namespace org.bouncycastle.bcpg
{

	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// Basic type for a user attribute sub-packet.
	/// </summary>
	public class UserAttributeSubpacket
	{
		internal int type;
		private bool forceLongLength; // we preserve this as not everyone encodes length properly.
		protected internal byte[] data;

		public UserAttributeSubpacket(int type, byte[] data) : this(type, false, data)
		{
		}

		public UserAttributeSubpacket(int type, bool forceLongLength, byte[] data)
		{
			this.type = type;
			this.forceLongLength = forceLongLength;
			this.data = data;
		}

		public virtual int getType()
		{
			return type;
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

			if (bodyLen < 192 && !forceLongLength)
			{
				@out.write((byte)bodyLen);
			}
			else if (bodyLen <= 8383 && !forceLongLength)
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

			@out.write(type);
			@out.write(data);
		}

		public override bool Equals(object o)
		{
			if (o == this)
			{
				return true;
			}

			if (!(o is UserAttributeSubpacket))
			{
				return false;
			}

			UserAttributeSubpacket other = (UserAttributeSubpacket)o;

			return this.type == other.type && Arrays.areEqual(this.data, other.data);
		}

		public override int GetHashCode()
		{
			return type ^ Arrays.GetHashCode(data);
		}
	}

}
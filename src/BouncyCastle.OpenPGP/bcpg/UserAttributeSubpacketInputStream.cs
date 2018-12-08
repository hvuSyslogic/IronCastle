namespace org.bouncycastle.bcpg
{

	using ImageAttribute = org.bouncycastle.bcpg.attr.ImageAttribute;

	/// <summary>
	/// reader for user attribute sub-packets
	/// </summary>
	public class UserAttributeSubpacketInputStream : InputStream, UserAttributeSubpacketTags
	{
		internal InputStream @in;

		public UserAttributeSubpacketInputStream(InputStream @in)
		{
			this.@in = @in;
		}

		public virtual int available()
		{
			return @in.available();
		}

		public virtual int read()
		{
			return @in.read();
		}

		private void readFully(byte[] buf, int off, int len)
		{
			if (len > 0)
			{
				int b = this.read();

				if (b < 0)
				{
					throw new EOFException();
				}

				buf[off] = (byte)b;
				off++;
				len--;
			}

			while (len > 0)
			{
				int l = @in.read(buf, off, len);

				if (l < 0)
				{
					throw new EOFException();
				}

				off += l;
				len -= l;
			}
		}

		public virtual UserAttributeSubpacket readPacket()
		{
			int l = this.read();
			int bodyLen = 0;
			bool longLength = false;

			if (l < 0)
			{
				return null;
			}

			if (l < 192)
			{
				bodyLen = l;
			}
			else if (l <= 223)
			{
				bodyLen = ((l - 192) << 8) + (@in.read()) + 192;
			}
			else if (l == 255)
			{
				bodyLen = (@in.read() << 24) | (@in.read() << 16) | (@in.read() << 8) | @in.read();
				longLength = true;
			}
			else
			{
				throw new IOException("unrecognised length reading user attribute sub packet");
			}

		   int tag = @in.read();

		   if (tag < 0)
		   {
			   throw new EOFException("unexpected EOF reading user attribute sub packet");
		   }

		   byte[] data = new byte[bodyLen - 1];

		   this.readFully(data, 0, data.Length);

		   int type = tag;

		   switch (type)
		   {
		   case UserAttributeSubpacketTags_Fields.IMAGE_ATTRIBUTE:
			   return new ImageAttribute(longLength, data);
		   }

		   return new UserAttributeSubpacket(type, longLength, data);
		}
	}

}
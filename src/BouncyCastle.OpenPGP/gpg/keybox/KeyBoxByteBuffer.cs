namespace org.bouncycastle.gpg.keybox
{

	/// <summary>
	/// Wraps an existing ByteArrayBuffer with support for unsigned int reads.
	/// Method names in the nomenclature of the spec.
	/// </summary>
	public class KeyBoxByteBuffer
	{
		private readonly ByteBuffer buffer;

		public KeyBoxByteBuffer(ByteBuffer buffer)
		{
			this.buffer = buffer;
		}

		internal static KeyBoxByteBuffer wrap(object src)
		{

			if (src == null)
			{
				return null;
			}
			else if (src is KeyBoxByteBuffer) // Same type.
			{
				return (KeyBoxByteBuffer)src;
			}
			else if (src is ByteBuffer) // ByteBuffer
			{
				return new KeyBoxByteBuffer((ByteBuffer)src);
			}
			else if (src is byte[]) // ByteArray
			{
				return wrap(ByteBuffer.wrap((byte[])src));
			}
			else if (src is ByteArrayOutputStream) // ByteArrayInputStream specifically.
			{
				return wrap(((ByteArrayOutputStream)src).toByteArray());
			}
			else if (src is InputStream) // InputStream
			{
				ByteArrayOutputStream bos = new ByteArrayOutputStream();

				byte[] buf = new byte[4096];
				int i;

				while ((i = ((InputStream)src).read(buf)) >= 0)
				{
					bos.write(buf, 0, i);
				}

				bos.flush();
				bos.close();

				return wrap(bos);
			}

			throw new IllegalStateException("Could not convert " + src.GetType().getCanonicalName() + " to KeyBoxByteBuffer");
		}

		public virtual int size()
		{
			return this.buffer.limit() - 20;
		}

		public virtual byte[] rangeOf(int start, int end)
		{
			int p = buffer.position();
			buffer.position(start);
			byte[] data = new byte[end - start];
			buffer.get(data);
			buffer.position(p);
			return data;
		}

		public virtual bool hasRemaining()
		{
			return buffer.hasRemaining();
		}

		public virtual int position()
		{
			return buffer.position();
		}

		public virtual void position(int p)
		{
			buffer.position(p);
		}

		public virtual int u16()
		{
			return (u8() << 8) | u8();
		}

		public virtual long u32()
		{
			return ((u8() << 24) | (u8() << 16) | (u8() << 8) | u8());
		}

		public virtual int u8()
		{
			return ((int)buffer.get() & 0xFF);
		}

		public virtual void bN(byte[] array)
		{
			buffer.get(array);
		}

		public virtual ByteBuffer getBuffer()
		{
			return buffer;
		}
	}

}
namespace org.bouncycastle.util
{
	/// <summary>
	/// Utility methods for converting byte arrays into ints and longs, and back again.
	/// </summary>
	public abstract class Pack
	{
		public static short bigEndianToShort(byte[] bs, int off)
		{
			int n = (bs[off] & 0xff) << 8;
			n |= (bs[++off] & 0xff);
			return (short)n;
		}

		public static int bigEndianToInt(byte[] bs, int off)
		{
			int n = bs[off] << 24;
			n |= (bs[++off] & 0xff) << 16;
			n |= (bs[++off] & 0xff) << 8;
			n |= (bs[++off] & 0xff);
			return n;
		}

		public static void bigEndianToInt(byte[] bs, int off, int[] ns)
		{
			for (int i = 0; i < ns.Length; ++i)
			{
				ns[i] = bigEndianToInt(bs, off);
				off += 4;
			}
		}

		public static byte[] intToBigEndian(int n)
		{
			byte[] bs = new byte[4];
			intToBigEndian(n, bs, 0);
			return bs;
		}

		public static void intToBigEndian(int n, byte[] bs, int off)
		{
			bs[off] = (byte)((int)((uint)n >> 24));
			bs[++off] = (byte)((int)((uint)n >> 16));
			bs[++off] = (byte)((int)((uint)n >> 8));
			bs[++off] = (byte)(n);
		}

	    public static void uintToBigEndian(uint n, byte[] bs, int off)
	    {
	        bs[off] = (byte)((int)(n >> 24));
	        bs[++off] = (byte)((int)(n >> 16));
	        bs[++off] = (byte)((int)(n >> 8));
	        bs[++off] = (byte)(n);
	    }

        public static byte[] intToBigEndian(int[] ns)
		{
			byte[] bs = new byte[4 * ns.Length];
			intToBigEndian(ns, bs, 0);
			return bs;
		}

		public static void intToBigEndian(int[] ns, byte[] bs, int off)
		{
			for (int i = 0; i < ns.Length; ++i)
			{
				intToBigEndian(ns[i], bs, off);
				off += 4;
			}
		}

		public static long bigEndianToLong(byte[] bs, int off)
		{
			int hi = bigEndianToInt(bs, off);
			int lo = bigEndianToInt(bs, off + 4);
			return ((long)(hi & 0xffffffffL) << 32) | (long)(lo & 0xffffffffL);
		}

	    public static ulong bigEndianToULong(byte[] bs, int off)
	    {
	        int hi = bigEndianToInt(bs, off);
	        int lo = bigEndianToInt(bs, off + 4);
	        return ((ulong)(hi & 0xffffffffL) << 32) | (ulong)(lo & 0xffffffffL);
	    }

        public static void bigEndianToLong(byte[] bs, int off, long[] ns)
		{
			for (int i = 0; i < ns.Length; ++i)
			{
				ns[i] = bigEndianToLong(bs, off);
				off += 8;
			}
		}

		public static byte[] longToBigEndian(long n)
		{
			byte[] bs = new byte[8];
			longToBigEndian(n, bs, 0);
			return bs;
		}

		public static void longToBigEndian(long n, byte[] bs, int off)
		{
			intToBigEndian((int)((long)((ulong)n >> 32)), bs, off);
			intToBigEndian(unchecked((int)(n & 0xffffffffL)), bs, off + 4);
		}

	    public static void UlongToBigEndian(ulong n, byte[] bs, int off)
	    {
	        uintToBigEndian((uint)((long)(n >> 32)), bs, off);
	        uintToBigEndian(unchecked((uint)(n & 0xffffffffL)), bs, off + 4);
	    }

        public static byte[] longToBigEndian(long[] ns)
		{
			byte[] bs = new byte[8 * ns.Length];
			longToBigEndian(ns, bs, 0);
			return bs;
		}

		public static void longToBigEndian(long[] ns, byte[] bs, int off)
		{
			for (int i = 0; i < ns.Length; ++i)
			{
				longToBigEndian(ns[i], bs, off);
				off += 8;
			}
		}

		public static short littleEndianToShort(byte[] bs, int off)
		{
			int n = bs[off] & 0xff;
			n |= (bs[++off] & 0xff) << 8;
			return (short)n;
		}

		public static int littleEndianToInt(byte[] bs, int off)
		{
			int n = bs[off] & 0xff;
			n |= (bs[++off] & 0xff) << 8;
			n |= (bs[++off] & 0xff) << 16;
			n |= bs[++off] << 24;
			return n;
		}

		public static void littleEndianToInt(byte[] bs, int off, int[] ns)
		{
			for (int i = 0; i < ns.Length; ++i)
			{
				ns[i] = littleEndianToInt(bs, off);
				off += 4;
			}
		}

		public static void littleEndianToInt(byte[] bs, int bOff, int[] ns, int nOff, int count)
		{
			for (int i = 0; i < count; ++i)
			{
				ns[nOff + i] = littleEndianToInt(bs, bOff);
				bOff += 4;
			}
		}

		public static int[] littleEndianToInt(byte[] bs, int off, int count)
		{
			int[] ns = new int[count];
			for (int i = 0; i < ns.Length; ++i)
			{
				ns[i] = littleEndianToInt(bs, off);
				off += 4;
			}
			return ns;
		}

		public static byte[] shortToLittleEndian(short n)
		{
			byte[] bs = new byte[2];
			shortToLittleEndian(n, bs, 0);
			return bs;
		}

		public static void shortToLittleEndian(short n, byte[] bs, int off)
		{
			bs[off] = (byte)(n);
			bs[++off] = (byte)((short)((ushort)n >> 8));
		}

		public static byte[] intToLittleEndian(int n)
		{
			byte[] bs = new byte[4];
			intToLittleEndian(n, bs, 0);
			return bs;
		}

		public static void intToLittleEndian(int n, byte[] bs, int off)
		{
			bs[off] = (byte)(n);
			bs[++off] = (byte)((int)((uint)n >> 8));
			bs[++off] = (byte)((int)((uint)n >> 16));
			bs[++off] = (byte)((int)((uint)n >> 24));
		}

		public static byte[] intToLittleEndian(int[] ns)
		{
			byte[] bs = new byte[4 * ns.Length];
			intToLittleEndian(ns, bs, 0);
			return bs;
		}

		public static void intToLittleEndian(int[] ns, byte[] bs, int off)
		{
			for (int i = 0; i < ns.Length; ++i)
			{
				intToLittleEndian(ns[i], bs, off);
				off += 4;
			}
		}

		public static long littleEndianToLong(byte[] bs, int off)
		{
			int lo = littleEndianToInt(bs, off);
			int hi = littleEndianToInt(bs, off + 4);
			return ((long)(hi & 0xffffffffL) << 32) | (long)(lo & 0xffffffffL);
		}

	    public static ulong littleEndianToULong(byte[] bs, int off)
	    {
	        int lo = littleEndianToInt(bs, off);
	        int hi = littleEndianToInt(bs, off + 4);
	        return ((ulong)(hi & 0xffffffffL) << 32) | (ulong)(lo & 0xffffffffL);
	    }

        public static void littleEndianToLong(byte[] bs, int off, long[] ns)
		{
			for (int i = 0; i < ns.Length; ++i)
			{
				ns[i] = littleEndianToLong(bs, off);
				off += 8;
			}
		}

	    public static void littleEndianToULong(byte[] bs, int off, ulong[] ns)
	    {
	        for (int i = 0; i < ns.Length; ++i)
	        {
	            ns[i] = littleEndianToULong(bs, off);
	            off += 8;
	        }
	    }

        public static void littleEndianToLong(byte[] bs, int bsOff, long[] ns, int nsOff, int nsLen)
		{
			for (int i = 0; i < nsLen; ++i)
			{
				ns[nsOff + i] = littleEndianToLong(bs, bsOff);
				bsOff += 8;
			}
		}

		public static byte[] longToLittleEndian(long n)
		{
			byte[] bs = new byte[8];
			longToLittleEndian(n, bs, 0);
			return bs;
		}

	    public static byte[] UlongToLittleEndian(ulong n)
	    {
	        byte[] bs = new byte[8];
	        UlongToLittleEndian(n, bs, 0);
	        return bs;
	    }

        public static void longToLittleEndian(long n, byte[] bs, int off)
		{
			intToLittleEndian(unchecked((int)(n & 0xffffffffL)), bs, off);
			intToLittleEndian((int)((long)((ulong)n >> 32)), bs, off + 4);
		}

	    public static void UlongToLittleEndian(ulong n, byte[] bs, int off)
	    {
	        intToLittleEndian(unchecked((int)(n & 0xffffffffL)), bs, off);
	        intToLittleEndian((int)((long)(n >> 32)), bs, off + 4);
	    }

        public static byte[] longToLittleEndian(long[] ns)
		{
			byte[] bs = new byte[8 * ns.Length];
			longToLittleEndian(ns, bs, 0);
			return bs;
		}

		public static void longToLittleEndian(long[] ns, byte[] bs, int off)
		{
			for (int i = 0; i < ns.Length; ++i)
			{
				longToLittleEndian(ns[i], bs, off);
				off += 8;
			}
		}

	    public static void UlongToLittleEndian(ulong[] ns, byte[] bs, int off)
	    {
	        for (int i = 0; i < ns.Length; ++i)
	        {
	            UlongToLittleEndian(ns[i], bs, off);
	            off += 8;
	        }
	    }

        public static void longToLittleEndian(long[] ns, int nsOff, int nsLen, byte[] bs, int bsOff)
		{
			for (int i = 0; i < nsLen; ++i)
			{
				longToLittleEndian(ns[nsOff + i], bs, bsOff);
				bsOff += 8;
			}
		}
	}

}
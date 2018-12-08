namespace org.bouncycastle.mime.encoding
{

	/// <summary>
	/// Reader for Base64 armored objects which converts them into binary data.
	/// </summary>
	public class Base64InputStream : InputStream
	{
		/*
		 * set up the decoding table.
		 */
		private static readonly byte[] decodingTable;

		static Base64InputStream()
		{
			decodingTable = new byte[128];

			for (int i = 'A'; i <= 'Z'; i++)
			{
				decodingTable[i] = (byte)(i - 'A');
			}

			for (int i = 'a'; i <= 'z'; i++)
			{
				decodingTable[i] = (byte)(i - 'a' + 26);
			}

			for (int i = '0'; i <= '9'; i++)
			{
				decodingTable[i] = (byte)(i - '0' + 52);
			}

			decodingTable['+'] = 62;
			decodingTable['/'] = 63;
		}

		/// <summary>
		/// decode the base 64 encoded input data.
		/// </summary>
		/// <returns> the offset the data starts in out. </returns>
		private int decode(int in0, int in1, int in2, int in3, int[] @out)
		{
			int b1, b2, b3, b4;

			if (in3 < 0)
			{
				throw new EOFException("unexpected end of file in armored stream.");
			}

			if (in2 == '=')
			{
				b1 = decodingTable[in0] & 0xff;
				b2 = decodingTable[in1] & 0xff;

				@out[2] = ((b1 << 2) | (b2 >> 4)) & 0xff;

				return 2;
			}
			else if (in3 == '=')
			{
				b1 = decodingTable[in0];
				b2 = decodingTable[in1];
				b3 = decodingTable[in2];

				@out[1] = ((b1 << 2) | (b2 >> 4)) & 0xff;
				@out[2] = ((b2 << 4) | (b3 >> 2)) & 0xff;

				return 1;
			}
			else
			{
				b1 = decodingTable[in0];
				b2 = decodingTable[in1];
				b3 = decodingTable[in2];
				b4 = decodingTable[in3];

				@out[0] = ((b1 << 2) | (b2 >> 4)) & 0xff;
				@out[1] = ((b2 << 4) | (b3 >> 2)) & 0xff;
				@out[2] = ((b3 << 6) | b4) & 0xff;

				return 0;
			}
		}

		internal InputStream @in;
		internal int[] outBuf = new int[3];
		internal int bufPtr = 3;
		internal bool isEndOfStream;

		/// <summary>
		/// Create a stream for reading a PGP armoured message, parsing up to a header
		/// and then reading the data that follows.
		/// </summary>
		/// <param name="in"> </param>
		public Base64InputStream(InputStream @in)
		{
			this.@in = @in;
		}

		public virtual int available()
		{
			return @in.available();
		}

		private int readIgnoreSpace()
		{
			int c = @in.read();

			while (c == ' ' || c == '\t')
			{
				c = @in.read();
			}

			return c;
		}

		public virtual int read()
		{
			int c;

			if (bufPtr > 2)
			{
				c = readIgnoreSpace();

				if (c == '\r' || c == '\n')
				{
					c = readIgnoreSpace();

					while (c == '\n' || c == '\r')
					{
						c = readIgnoreSpace();
					}

					if (c < 0) // EOF
					{
						isEndOfStream = true;
						return -1;
					}

					bufPtr = decode(c, readIgnoreSpace(), readIgnoreSpace(), readIgnoreSpace(), outBuf);
				}
				else
				{
					if (c >= 0)
					{
						bufPtr = decode(c, readIgnoreSpace(), readIgnoreSpace(), readIgnoreSpace(), outBuf);
					}
					else
					{
						isEndOfStream = true;
						return -1;
					}
				}
			}

			c = outBuf[bufPtr++];

			return c;
		}

		public virtual void close()
		{
			@in.close();
		}
	}

}
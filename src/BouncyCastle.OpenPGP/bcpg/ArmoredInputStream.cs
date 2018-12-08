namespace org.bouncycastle.bcpg
{

	using StringList = org.bouncycastle.util.StringList;
	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// reader for Base64 armored objects - read the headers and then start returning
	/// bytes when the data is reached. An IOException is thrown if the CRC check
	/// fails.
	/// </summary>
	public class ArmoredInputStream : InputStream
	{
		/*
		 * set up the decoding table.
		 */
		private static readonly byte[] decodingTable;

		static ArmoredInputStream()
		{
			decodingTable = new byte[128];

			for (int i = 0; i < decodingTable.Length; i++)
			{
				decodingTable[i] = unchecked((byte)0xff);
			}

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

				if ((b1 | b2) < 0)
				{
					throw new IOException("invalid armor");
				}

				@out[2] = ((b1 << 2) | (b2 >> 4)) & 0xff;

				return 2;
			}
			else if (in3 == '=')
			{
				b1 = decodingTable[in0];
				b2 = decodingTable[in1];
				b3 = decodingTable[in2];

				if ((b1 | b2 | b3) < 0)
				{
					throw new IOException("invalid armor");
				}

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

				if ((b1 | b2 | b3 | b4) < 0)
				{
					throw new IOException("invalid armor");
				}

				@out[0] = ((b1 << 2) | (b2 >> 4)) & 0xff;
				@out[1] = ((b2 << 4) | (b3 >> 2)) & 0xff;
				@out[2] = ((b3 << 6) | b4) & 0xff;

				return 0;
			}
		}

		internal InputStream @in;
		internal bool start = true;
		internal int[] outBuf = new int[3];
		internal int bufPtr = 3;
		internal CRC24 crc = new CRC24();
		internal bool crcFound = false;
		internal bool hasHeaders = true;
		internal string header = null;
		internal bool newLineFound = false;
		internal bool clearText = false;
		internal bool restart = false;
		internal StringList headerList = Strings.newList();
		internal int lastC = 0;
//JAVA TO C# CONVERTER NOTE: Fields cannot have the same name as methods:
		internal bool isEndOfStream_Renamed;

		/// <summary>
		/// Create a stream for reading a PGP armoured message, parsing up to a header 
		/// and then reading the data that follows.
		/// </summary>
		/// <param name="in"> </param>
		public ArmoredInputStream(InputStream @in) : this(@in, true)
		{
		}

		/// <summary>
		/// Create an armoured input stream which will assume the data starts
		/// straight away, or parse for headers first depending on the value of 
		/// hasHeaders.
		/// </summary>
		/// <param name="in"> </param>
		/// <param name="hasHeaders"> true if headers are to be looked for, false otherwise. </param>
		public ArmoredInputStream(InputStream @in, bool hasHeaders)
		{
			this.@in = @in;
			this.hasHeaders = hasHeaders;

			if (hasHeaders)
			{
				parseHeaders();
			}

			start = false;
		}

		public virtual int available()
		{
			return @in.available();
		}

		private bool parseHeaders()
		{
			header = null;

			int c;
			int last = 0;
			bool headerFound = false;

			headerList = Strings.newList();

			//
			// if restart we already have a header
			//
			if (restart)
			{
				headerFound = true;
			}
			else
			{
				while ((c = @in.read()) >= 0)
				{
					if (c == '-' && (last == 0 || last == '\n' || last == '\r'))
					{
						headerFound = true;
						break;
					}

					last = c;
				}
			}

			if (headerFound)
			{
				StringBuffer buf = new StringBuffer("-");
				bool eolReached = false;
				bool crLf = false;

				if (restart) // we've had to look ahead two '-'
				{
					buf.append('-');
				}

				while ((c = @in.read()) >= 0)
				{
					if (last == '\r' && c == '\n')
					{
						crLf = true;
					}
					if (eolReached && (last != '\r' && c == '\n'))
					{
						break;
					}
					if (eolReached && c == '\r')
					{
						break;
					}
					if (c == '\r' || (last != '\r' && c == '\n'))
					{
						string line = buf.ToString();
						if (line.Trim().Length == 0)
						{
							break;
						}
						headerList.add(line);
						buf.setLength(0);
					}

					if (c != '\n' && c != '\r')
					{
						buf.append((char)c);
						eolReached = false;
					}
					else
					{
						if (c == '\r' || (last != '\r' && c == '\n'))
						{
							eolReached = true;
						}
					}

					last = c;
				}

				if (crLf)
				{
					@in.read(); // skip last \n
				}
			}

			if (headerList.size() > 0)
			{
				header = headerList.get(0);
			}

			clearText = "-----BEGIN PGP SIGNED MESSAGE-----".Equals(header);
			newLineFound = true;

			return headerFound;
		}

		/// <returns> true if we are inside the clear text section of a PGP
		/// signed message. </returns>
		public virtual bool isClearText()
		{
			return clearText;
		}

		/// <returns> true if the stream is actually at end of file. </returns>
		public virtual bool isEndOfStream()
		{
			return isEndOfStream_Renamed;
		}

		/// <summary>
		/// Return the armor header line (if there is one) </summary>
		/// <returns> the armor header line, null if none present. </returns>
		public virtual string getArmorHeaderLine()
		{
			return header;
		}

		/// <summary>
		/// Return the armor headers (the lines after the armor header line), </summary>
		/// <returns> an array of armor headers, null if there aren't any. </returns>
		public virtual string[] getArmorHeaders()
		{
			if (headerList.size() <= 1)
			{
				return null;
			}

			return headerList.toStringArray(1, headerList.size());
		}

		private int readIgnoreSpace()
		{
			int c = @in.read();

			while (c == ' ' || c == '\t')
			{
				c = @in.read();
			}

			if (c >= 128)
			{
				throw new IOException("invalid armor");
			}

			return c;
		}

		public virtual int read()
		{
			int c;

			if (start)
			{
				if (hasHeaders)
				{
					parseHeaders();
				}

				crc.reset();
				start = false;
			}

			if (clearText)
			{
				c = @in.read();

				if (c == '\r' || (c == '\n' && lastC != '\r'))
				{
					newLineFound = true;
				}
				else if (newLineFound && c == '-')
				{
					c = @in.read();
					if (c == '-') // a header, not dash escaped
					{
						clearText = false;
						start = true;
						restart = true;
					}
					else // a space - must be a dash escape
					{
						c = @in.read();
					}
					newLineFound = false;
				}
				else
				{
					if (c != '\n' && lastC != '\r')
					{
						newLineFound = false;
					}
				}

				lastC = c;

				if (c < 0)
				{
					isEndOfStream_Renamed = true;
				}

				return c;
			}

			if (bufPtr > 2 || crcFound)
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
						isEndOfStream_Renamed = true;
						return -1;
					}

					if (c == '=') // crc reached
					{
						bufPtr = decode(readIgnoreSpace(), readIgnoreSpace(), readIgnoreSpace(), readIgnoreSpace(), outBuf);
						if (bufPtr == 0)
						{
							int i = ((outBuf[0] & 0xff) << 16) | ((outBuf[1] & 0xff) << 8) | (outBuf[2] & 0xff);

							crcFound = true;

							if (i != crc.getValue())
							{
								throw new IOException("crc check failed in armored message.");
							}
							return read();
						}
						else
						{
							throw new IOException("no crc found in armored message.");
						}
					}
					else if (c == '-') // end of record reached
					{
						while ((c = @in.read()) >= 0)
						{
							if (c == '\n' || c == '\r')
							{
								break;
							}
						}

						if (!crcFound)
						{
							throw new IOException("crc check not found.");
						}

						crcFound = false;
						start = true;
						bufPtr = 3;

						if (c < 0)
						{
							isEndOfStream_Renamed = true;
						}

						return -1;
					}
					else // data
					{
						bufPtr = decode(c, readIgnoreSpace(), readIgnoreSpace(), readIgnoreSpace(), outBuf);
					}
				}
				else
				{
					if (c >= 0)
					{
						bufPtr = decode(c, readIgnoreSpace(), readIgnoreSpace(), readIgnoreSpace(), outBuf);
					}
					else
					{
						isEndOfStream_Renamed = true;
						return -1;
					}
				}
			}

			c = outBuf[bufPtr++];

			crc.update(c);

			return c;
		}

		public virtual void close()
		{
			@in.close();
		}
	}

}
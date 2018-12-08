namespace org.bouncycastle.bcpg
{

	using Streams = org.bouncycastle.util.io.Streams;

	/// <summary>
	/// Stream reader for PGP objects
	/// </summary>
	public class BCPGInputStream : InputStream, PacketTags
	{
		internal InputStream @in;
		internal bool next = false;
		internal int nextB;

		public BCPGInputStream(InputStream @in)
		{
			this.@in = @in;
		}

		public virtual int available()
		{
			return @in.available();
		}

		public virtual int read()
		{
			if (next)
			{
				next = false;

				return nextB;
			}
			else
			{
				return @in.read();
			}
		}

		public virtual int read(byte[] buf, int off, int len)
		{
			if (len == 0)
			{
				return 0;
			}

			if (!next)
			{
				return @in.read(buf, off, len);
			}

			// We have next byte waiting, so return it

			if (nextB < 0)
			{
				return -1; // EOF
			}

			buf[off] = (byte)nextB; // May throw NullPointerException...
			next = false; // ...so only set this afterwards

			return 1;
		}

		public virtual void readFully(byte[] buf, int off, int len)
		{
			if (Streams.readFully(this, buf, off, len) < len)
			{
				throw new EOFException();
			}
		}

		public virtual byte[] readAll()
		{
			return Streams.readAll(this);
		}

		public virtual void readFully(byte[] buf)
		{
			readFully(buf, 0, buf.Length);
		}

		/// <summary>
		/// Obtains the tag of the next packet in the stream.
		/// </summary>
		/// <returns> the <seealso cref="PacketTags tag number"/>.
		/// </returns>
		/// <exception cref="IOException"> if an error occurs reading the tag from the stream. </exception>
		public virtual int nextPacketTag()
		{
			if (!next)
			{
				try
				{
					nextB = @in.read();
				}
				catch (EOFException)
				{
					nextB = -1;
				}

				next = true;
			}

			if (nextB < 0)
			{
				return nextB;
			}

			int maskB = nextB & 0x3f;
			if ((nextB & 0x40) == 0) // old
			{
				maskB >>= 2;
			}
			return maskB;
		}

		/// <summary>
		/// Reads the next packet from the stream. </summary>
		/// <exception cref="IOException"> </exception>
		public virtual Packet readPacket()
		{
			int hdr = this.read();

			if (hdr < 0)
			{
				return null;
			}

			if ((hdr & 0x80) == 0)
			{
				throw new IOException("invalid header encountered");
			}

			bool newPacket = (hdr & 0x40) != 0;
			int tag = 0;
			int bodyLen = 0;
			bool partial = false;

			if (newPacket)
			{
				tag = hdr & 0x3f;

				int l = this.read();

				if (l < 192)
				{
					bodyLen = l;
				}
				else if (l <= 223)
				{
					int b = @in.read();

					bodyLen = ((l - 192) << 8) + (b) + 192;
				}
				else if (l == 255)
				{
					bodyLen = (@in.read() << 24) | (@in.read() << 16) | (@in.read() << 8) | @in.read();
				}
				else
				{
					partial = true;
					bodyLen = 1 << (l & 0x1f);
				}
			}
			else
			{
				int lengthType = hdr & 0x3;

				tag = (hdr & 0x3f) >> 2;

				switch (lengthType)
				{
				case 0:
					bodyLen = this.read();
					break;
				case 1:
					bodyLen = (this.read() << 8) | this.read();
					break;
				case 2:
					bodyLen = (this.read() << 24) | (this.read() << 16) | (this.read() << 8) | this.read();
					break;
				case 3:
					partial = true;
					break;
				default:
					throw new IOException("unknown length type encountered");
				}
			}

			BCPGInputStream objStream;

			if (bodyLen == 0 && partial)
			{
				objStream = this;
			}
			else
			{
				objStream = new BCPGInputStream(new PartialInputStream(this, partial, bodyLen));
			}

			switch (tag)
			{
			case PacketTags_Fields.RESERVED:
				return new InputStreamPacket(objStream);
			case PacketTags_Fields.PUBLIC_KEY_ENC_SESSION:
				return new PublicKeyEncSessionPacket(objStream);
			case PacketTags_Fields.SIGNATURE:
				return new SignaturePacket(objStream);
			case PacketTags_Fields.SYMMETRIC_KEY_ENC_SESSION:
				return new SymmetricKeyEncSessionPacket(objStream);
			case PacketTags_Fields.ONE_PASS_SIGNATURE:
				return new OnePassSignaturePacket(objStream);
			case PacketTags_Fields.SECRET_KEY:
				return new SecretKeyPacket(objStream);
			case PacketTags_Fields.PUBLIC_KEY:
				return new PublicKeyPacket(objStream);
			case PacketTags_Fields.SECRET_SUBKEY:
				return new SecretSubkeyPacket(objStream);
			case PacketTags_Fields.COMPRESSED_DATA:
				return new CompressedDataPacket(objStream);
			case PacketTags_Fields.SYMMETRIC_KEY_ENC:
				return new SymmetricEncDataPacket(objStream);
			case PacketTags_Fields.MARKER:
				return new MarkerPacket(objStream);
			case PacketTags_Fields.LITERAL_DATA:
				return new LiteralDataPacket(objStream);
			case PacketTags_Fields.TRUST:
				return new TrustPacket(objStream);
			case PacketTags_Fields.USER_ID:
				return new UserIDPacket(objStream);
			case PacketTags_Fields.USER_ATTRIBUTE:
				return new UserAttributePacket(objStream);
			case PacketTags_Fields.PUBLIC_SUBKEY:
				return new PublicSubkeyPacket(objStream);
			case PacketTags_Fields.SYM_ENC_INTEGRITY_PRO:
				return new SymmetricEncIntegrityPacket(objStream);
			case PacketTags_Fields.MOD_DETECTION_CODE:
				return new ModDetectionCodePacket(objStream);
			case PacketTags_Fields.EXPERIMENTAL_1:
			case PacketTags_Fields.EXPERIMENTAL_2:
			case PacketTags_Fields.EXPERIMENTAL_3:
			case PacketTags_Fields.EXPERIMENTAL_4:
				return new ExperimentalPacket(tag, objStream);
			default:
				throw new IOException("unknown packet type encountered: " + tag);
			}
		}

		public virtual void close()
		{
			@in.close();
		}

		/// <summary>
		/// a stream that overlays our input stream, allowing the user to only read a segment of it.
		/// 
		/// NB: dataLength will be negative if the segment length is in the upper range above 2**31.
		/// </summary>
		public class PartialInputStream : InputStream
		{
			internal BCPGInputStream @in;
			internal bool partial;
			internal int dataLength;

			public PartialInputStream(BCPGInputStream @in, bool partial, int dataLength)
			{
				this.@in = @in;
				this.partial = partial;
				this.dataLength = dataLength;
			}

			public virtual int available()
			{
				int avail = @in.available();

				if (avail <= dataLength || dataLength < 0)
				{
					return avail;
				}
				else
				{
					if (partial && dataLength == 0)
					{
						return 1;
					}
					return dataLength;
				}
			}

			public virtual int loadDataLength()
			{
				int l = @in.read();

				if (l < 0)
				{
					return -1;
				}

				partial = false;
				if (l < 192)
				{
					dataLength = l;
				}
				else if (l <= 223)
				{
					dataLength = ((l - 192) << 8) + (@in.read()) + 192;
				}
				else if (l == 255)
				{
					dataLength = (@in.read() << 24) | (@in.read() << 16) | (@in.read() << 8) | @in.read();
				}
				else
				{
					partial = true;
					dataLength = 1 << (l & 0x1f);
				}

				return dataLength;
			}

			public virtual int read(byte[] buf, int offset, int len)
			{
				do
				{
					if (dataLength != 0)
					{
						int readLen = (dataLength > len || dataLength < 0) ? len : dataLength;
						readLen = @in.read(buf, offset, readLen);
						if (readLen < 0)
						{
							throw new EOFException("premature end of stream in PartialInputStream");
						}
						dataLength -= readLen;
						return readLen;
					}
				} while (partial && loadDataLength() >= 0);

				return -1;
			}

			public virtual int read()
			{
				do
				{
					if (dataLength != 0)
					{
						int ch = @in.read();
						if (ch < 0)
						{
							throw new EOFException("premature end of stream in PartialInputStream");
						}
						dataLength--;
						return ch;
					}
				} while (partial && loadDataLength() >= 0);

				return -1;
			}
		}
	}

}
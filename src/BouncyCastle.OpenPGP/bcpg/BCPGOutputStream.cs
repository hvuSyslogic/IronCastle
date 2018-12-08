namespace org.bouncycastle.bcpg
{

	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// Basic output stream.
	/// </summary>
	public class BCPGOutputStream : OutputStream, PacketTags, CompressionAlgorithmTags
	{
		internal OutputStream @out;
		private byte[] partialBuffer;
		private int partialBufferLength;
		private int partialPower;
		private int partialOffset;

		private const int BUF_SIZE_POWER = 16; // 2^16 size buffer on long files

		public BCPGOutputStream(OutputStream @out)
		{
			this.@out = @out;
		}

		/// <summary>
		/// Create a stream representing an old style partial object.
		/// </summary>
		/// <param name="tag"> the packet tag for the object. </param>
		public BCPGOutputStream(OutputStream @out, int tag)
		{
			this.@out = @out;
			this.writeHeader(tag, true, true, 0);
		}

		/// <summary>
		/// Create a stream representing a general packet.
		/// </summary>
		/// <param name="out"> </param>
		/// <param name="tag"> </param>
		/// <param name="length"> </param>
		/// <param name="oldFormat"> </param>
		/// <exception cref="IOException"> </exception>
		public BCPGOutputStream(OutputStream @out, int tag, long length, bool oldFormat)
		{
			this.@out = @out;

			if (length > 0xFFFFFFFFL)
			{
				this.writeHeader(tag, false, true, 0);
				this.partialBufferLength = 1 << BUF_SIZE_POWER;
				this.partialBuffer = new byte[partialBufferLength];
				this.partialPower = BUF_SIZE_POWER;
				this.partialOffset = 0;
			}
			else
			{
				this.writeHeader(tag, oldFormat, false, length);
			}
		}

		/// 
		/// <param name="tag"> </param>
		/// <param name="length"> </param>
		/// <exception cref="IOException"> </exception>
		public BCPGOutputStream(OutputStream @out, int tag, long length)
		{
			this.@out = @out;

			this.writeHeader(tag, false, false, length);
		}

		/// <summary>
		/// Create a new style partial input stream buffered into chunks.
		/// </summary>
		/// <param name="out"> output stream to write to. </param>
		/// <param name="tag"> packet tag. </param>
		/// <param name="buffer"> size of chunks making up the packet. </param>
		/// <exception cref="IOException"> </exception>
		public BCPGOutputStream(OutputStream @out, int tag, byte[] buffer)
		{
			this.@out = @out;
			this.writeHeader(tag, false, true, 0);

			this.partialBuffer = buffer;

			int length = partialBuffer.Length;

			for (partialPower = 0; length != 1; partialPower++)
			{
				length = (int)((uint)length >> 1);
			}

			if (partialPower > 30)
			{
				throw new IOException("Buffer cannot be greater than 2^30 in length.");
			}

			this.partialBufferLength = 1 << partialPower;
			this.partialOffset = 0;
		}

		private void writeNewPacketLength(long bodyLen)
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

		private void writeHeader(int tag, bool oldPackets, bool partial, long bodyLen)
		{
			int hdr = 0x80;

			if (partialBuffer != null)
			{
				partialFlush(true);
				partialBuffer = null;
			}

			if (oldPackets)
			{
				hdr |= tag << 2;

				if (partial)
				{
					this.write(hdr | 0x03);
				}
				else
				{
					if (bodyLen <= 0xff)
					{
						this.write(hdr);
						this.write((byte)bodyLen);
					}
					else if (bodyLen <= 0xffff)
					{
						this.write(hdr | 0x01);
						this.write((byte)(bodyLen >> 8));
						this.write((byte)(bodyLen));
					}
					else
					{
						this.write(hdr | 0x02);
						this.write((byte)(bodyLen >> 24));
						this.write((byte)(bodyLen >> 16));
						this.write((byte)(bodyLen >> 8));
						this.write((byte)bodyLen);
					}
				}
			}
			else
			{
				hdr |= 0x40 | tag;
				this.write(hdr);

				if (partial)
				{
					partialOffset = 0;
				}
				else
				{
					this.writeNewPacketLength(bodyLen);
				}
			}
		}

		private void partialFlush(bool isLast)
		{
			if (isLast)
			{
				writeNewPacketLength(partialOffset);
				@out.write(partialBuffer, 0, partialOffset);
			}
			else
			{
				@out.write(0xE0 | partialPower);
				@out.write(partialBuffer, 0, partialBufferLength);
			}

			partialOffset = 0;
		}

		private void writePartial(byte b)
		{
			if (partialOffset == partialBufferLength)
			{
				partialFlush(false);
			}

			partialBuffer[partialOffset++] = b;
		}

		private void writePartial(byte[] buf, int off, int len)
		{
			if (partialOffset == partialBufferLength)
			{
				partialFlush(false);
			}

			if (len <= (partialBufferLength - partialOffset))
			{
				JavaSystem.arraycopy(buf, off, partialBuffer, partialOffset, len);
				partialOffset += len;
			}
			else
			{
				JavaSystem.arraycopy(buf, off, partialBuffer, partialOffset, partialBufferLength - partialOffset);
				off += partialBufferLength - partialOffset;
				len -= partialBufferLength - partialOffset;
				partialFlush(false);

				while (len > partialBufferLength)
				{
					JavaSystem.arraycopy(buf, off, partialBuffer, 0, partialBufferLength);
					off += partialBufferLength;
					len -= partialBufferLength;
					partialFlush(false);
				}

				JavaSystem.arraycopy(buf, off, partialBuffer, 0, len);
				partialOffset += len;
			}
		}

		public virtual void write(int b)
		{
			if (partialBuffer != null)
			{
				writePartial((byte)b);
			}
			else
			{
				@out.write(b);
			}
		}

		public virtual void write(byte[] bytes, int off, int len)
		{
			if (partialBuffer != null)
			{
				writePartial(bytes, off, len);
			}
			else
			{
				@out.write(bytes, off, len);
			}
		}

		public virtual void writePacket(ContainedPacket p)
		{
			p.encode(this);
		}

		public virtual void writePacket(int tag, byte[] body, bool oldFormat)
		{
			this.writeHeader(tag, oldFormat, false, body.Length);
			this.write(body);
		}

		public virtual void writeObject(BCPGObject o)
		{
			o.encode(this);
		}

		/// <summary>
		/// Flush the underlying stream.
		/// </summary>
		public virtual void flush()
		{
			@out.flush();
		}

		/// <summary>
		/// Finish writing out the current packet without closing the underlying stream.
		/// </summary>
		public virtual void finish()
		{
			if (partialBuffer != null)
			{
				partialFlush(true);
				Arrays.fill(partialBuffer, (byte)0);
				partialBuffer = null;
			}
		}

		public virtual void close()
		{
			this.finish();
			@out.flush();
			@out.close();
		}
	}

}
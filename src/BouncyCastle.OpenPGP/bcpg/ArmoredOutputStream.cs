namespace org.bouncycastle.bcpg
{

	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// Output stream that writes data in ASCII Armored format.
	/// <para>
	/// Note 1: close() needs to be called on an ArmoredOutputStream to write the final checksum. flush() will not do this as
	/// other classes assume it is always fine to call flush() - it is not though if the checksum gets output.
	/// Note 2: as multiple PGP blobs are often written to the same stream, close() does not close the underlying stream.
	/// </para>
	/// </summary>
	public class ArmoredOutputStream : OutputStream
	{
		public const string VERSION_HDR = "Version";

		private static readonly byte[] encodingTable = new byte[] {(byte)'A', (byte)'B', (byte)'C', (byte)'D', (byte)'E', (byte)'F', (byte)'G', (byte)'H', (byte)'I', (byte)'J', (byte)'K', (byte)'L', (byte)'M', (byte)'N', (byte)'O', (byte)'P', (byte)'Q', (byte)'R', (byte)'S', (byte)'T', (byte)'U', (byte)'V', (byte)'W', (byte)'X', (byte)'Y', (byte)'Z', (byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e', (byte)'f', (byte)'g', (byte)'h', (byte)'i', (byte)'j', (byte)'k', (byte)'l', (byte)'m', (byte)'n', (byte)'o', (byte)'p', (byte)'q', (byte)'r', (byte)'s', (byte)'t', (byte)'u', (byte)'v', (byte)'w', (byte)'x', (byte)'y', (byte)'z', (byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5', (byte)'6', (byte)'7', (byte)'8', (byte)'9', (byte)'+', (byte)'/'};

		/// <summary>
		/// encode the input data producing a base 64 encoded byte array.
		/// </summary>
		private void encode(OutputStream @out, int[] data, int len)
		{
			int d1, d2, d3;

			switch (len)
			{
			case 0: // nothing left to do
				break;
			case 1:
				d1 = data[0];

				@out.write(encodingTable[((int)((uint)d1 >> 2)) & 0x3f]);
				@out.write(encodingTable[(d1 << 4) & 0x3f]);
				@out.write('=');
				@out.write('=');
				break;
			case 2:
				d1 = data[0];
				d2 = data[1];

				@out.write(encodingTable[((int)((uint)d1 >> 2)) & 0x3f]);
				@out.write(encodingTable[((d1 << 4) | ((int)((uint)d2 >> 4))) & 0x3f]);
				@out.write(encodingTable[(d2 << 2) & 0x3f]);
				@out.write('=');
				break;
			case 3:
				d1 = data[0];
				d2 = data[1];
				d3 = data[2];

				@out.write(encodingTable[((int)((uint)d1 >> 2)) & 0x3f]);
				@out.write(encodingTable[((d1 << 4) | ((int)((uint)d2 >> 4))) & 0x3f]);
				@out.write(encodingTable[((d2 << 2) | ((int)((uint)d3 >> 6))) & 0x3f]);
				@out.write(encodingTable[d3 & 0x3f]);
				break;
			default:
				throw new IOException("unknown length in encode");
			}
		}

		internal OutputStream @out;
		internal int[] buf = new int[3];
		internal int bufPtr = 0;
		internal CRC24 crc = new CRC24();
		internal int chunkCount = 0;
		internal int lastb;

		internal bool start = true;
		internal bool clearText = false;
		internal bool newLine = false;

		internal string nl = Strings.lineSeparator();

		internal string type;
		internal string headerStart = "-----BEGIN PGP ";
		internal string headerTail = "-----";
		internal string footerStart = "-----END PGP ";
		internal string footerTail = "-----";

		internal string version = "BCPG v@RELEASE_NAME@";

		internal Hashtable headers = new Hashtable();

		/// <summary>
		/// Constructs an armored output stream with <seealso cref="#resetHeaders() default headers"/>.
		/// </summary>
		/// <param name="out"> the OutputStream to wrap. </param>
		public ArmoredOutputStream(OutputStream @out)
		{
			this.@out = @out;

			if (string.ReferenceEquals(nl, null))
			{
				nl = "\r\n";
			}

			headers.put(VERSION_HDR, version);
		}

		/// <summary>
		/// Constructs an armored output stream with default and custom headers.
		/// </summary>
		/// <param name="out"> the OutputStream to wrap. </param>
		/// <param name="headers"> additional headers that add to or override the {@link #resetHeaders() default
		///            headers}. </param>
		public ArmoredOutputStream(OutputStream @out, Hashtable headers) : this(@out)
		{

			Enumeration e = headers.keys();

			while (e.hasMoreElements())
			{
				object key = e.nextElement();

				this.headers.put(key, headers.get(key));
			}
		}

		/// <summary>
		/// Set an additional header entry. A null value will clear the entry for name.
		/// </summary>
		/// <param name="name"> the name of the header entry. </param>
		/// <param name="value"> the value of the header entry. </param>
		public virtual void setHeader(string name, string value)
		{
			if (string.ReferenceEquals(value, null))
			{
				this.headers.remove(name);
			}
			else
			{
				this.headers.put(name, value);
			}
		}

		/// <summary>
		/// Reset the headers to only contain a Version string (if one is present)
		/// </summary>
		public virtual void resetHeaders()
		{
			string version = (string)headers.get(VERSION_HDR);

			headers.clear();

			if (!string.ReferenceEquals(version, null))
			{
				headers.put(VERSION_HDR, version);
			}
		}

		/// <summary>
		/// Start a clear text signed message. </summary>
		/// <param name="hashAlgorithm"> </param>
		public virtual void beginClearText(int hashAlgorithm)
		{
			string hash;

			switch (hashAlgorithm)
			{
			case HashAlgorithmTags_Fields.SHA1:
				hash = "SHA1";
				break;
			case HashAlgorithmTags_Fields.SHA256:
				hash = "SHA256";
				break;
			case HashAlgorithmTags_Fields.SHA384:
				hash = "SHA384";
				break;
			case HashAlgorithmTags_Fields.SHA512:
				hash = "SHA512";
				break;
			case HashAlgorithmTags_Fields.MD2:
				hash = "MD2";
				break;
			case HashAlgorithmTags_Fields.MD5:
				hash = "MD5";
				break;
			case HashAlgorithmTags_Fields.RIPEMD160:
				hash = "RIPEMD160";
				break;
			default:
				throw new IOException("unknown hash algorithm tag in beginClearText: " + hashAlgorithm);
			}

			string armorHdr = "-----BEGIN PGP SIGNED MESSAGE-----" + nl;
			string hdrs = "Hash: " + hash + nl + nl;

			for (int i = 0; i != armorHdr.Length; i++)
			{
				@out.write(armorHdr[i]);
			}

			for (int i = 0; i != hdrs.Length; i++)
			{
				@out.write(hdrs[i]);
			}

			clearText = true;
			newLine = true;
			lastb = 0;
		}

		public virtual void endClearText()
		{
			clearText = false;
		}

		private void writeHeaderEntry(string name, string value)
		{
			for (int i = 0; i != name.Length; i++)
			{
				@out.write(name[i]);
			}

			@out.write(':');
			@out.write(' ');

			for (int i = 0; i != value.Length; i++)
			{
				@out.write(value[i]);
			}

			for (int i = 0; i != nl.Length; i++)
			{
				@out.write(nl[i]);
			}
		}

		public virtual void write(int b)
		{
			if (clearText)
			{
				@out.write(b);

				if (newLine)
				{
					if (!(b == '\n' && lastb == '\r'))
					{
						newLine = false;
					}
					if (b == '-')
					{
						@out.write(' ');
						@out.write('-'); // dash escape
					}
				}
				if (b == '\r' || (b == '\n' && lastb != '\r'))
				{
					newLine = true;
				}
				lastb = b;
				return;
			}

			if (start)
			{
				bool newPacket = (b & 0x40) != 0;
				int tag = 0;

				if (newPacket)
				{
					tag = b & 0x3f;
				}
				else
				{
					tag = (b & 0x3f) >> 2;
				}

				switch (tag)
				{
				case PacketTags_Fields.PUBLIC_KEY:
					type = "PUBLIC KEY BLOCK";
					break;
				case PacketTags_Fields.SECRET_KEY:
					type = "PRIVATE KEY BLOCK";
					break;
				case PacketTags_Fields.SIGNATURE:
					type = "SIGNATURE";
					break;
				default:
					type = "MESSAGE";
				break;
				}

				for (int i = 0; i != headerStart.Length; i++)
				{
					@out.write(headerStart[i]);
				}

				for (int i = 0; i != type.Length; i++)
				{
					@out.write(type[i]);
				}

				for (int i = 0; i != headerTail.Length; i++)
				{
					@out.write(headerTail[i]);
				}

				for (int i = 0; i != nl.Length; i++)
				{
					@out.write(nl[i]);
				}

				if (headers.containsKey(VERSION_HDR))
				{
					writeHeaderEntry(VERSION_HDR, (string)headers.get(VERSION_HDR));
				}

				Enumeration e = headers.keys();
				while (e.hasMoreElements())
				{
					string key = (string)e.nextElement();

					if (!key.Equals(VERSION_HDR))
					{
						writeHeaderEntry(key, (string)headers.get(key));
					}
				}

				for (int i = 0; i != nl.Length; i++)
				{
					@out.write(nl[i]);
				}

				start = false;
			}

			if (bufPtr == 3)
			{
				encode(@out, buf, bufPtr);
				bufPtr = 0;
				if ((++chunkCount & 0xf) == 0)
				{
					for (int i = 0; i != nl.Length; i++)
					{
						@out.write(nl[i]);
					}
				}
			}

			crc.update(b);
			buf[bufPtr++] = b & 0xff;
		}

		public virtual void flush()
		{
		}

		/// <summary>
		/// <b>Note</b>: close() does not close the underlying stream. So it is possible to write
		/// multiple objects using armoring to a single stream.
		/// </summary>
		public virtual void close()
		{
			if (!string.ReferenceEquals(type, null))
			{
				encode(@out, buf, bufPtr);

				for (int i = 0; i != nl.Length; i++)
				{
					@out.write(nl[i]);
				}
				@out.write('=');

				int crcV = crc.getValue();

				buf[0] = ((crcV >> 16) & 0xff);
				buf[1] = ((crcV >> 8) & 0xff);
				buf[2] = (crcV & 0xff);

				encode(@out, buf, 3);

				for (int i = 0; i != nl.Length; i++)
				{
					@out.write(nl[i]);
				}

				for (int i = 0; i != footerStart.Length; i++)
				{
					@out.write(footerStart[i]);
				}

				for (int i = 0; i != type.Length; i++)
				{
					@out.write(type[i]);
				}

				for (int i = 0; i != footerTail.Length; i++)
				{
					@out.write(footerTail[i]);
				}

				for (int i = 0; i != nl.Length; i++)
				{
					@out.write(nl[i]);
				}

				@out.flush();

				type = null;
				start = true;
			}
		}
	}

}
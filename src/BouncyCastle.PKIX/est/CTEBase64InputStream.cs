using System;

namespace org.bouncycastle.est
{

	using Base64 = org.bouncycastle.util.encoders.Base64;


	public class CTEBase64InputStream : InputStream
	{
		protected internal readonly InputStream src;
		protected internal readonly byte[] rawBuf = new byte[1024];
		protected internal readonly byte[] data = new byte[768];
		protected internal readonly OutputStream dataOutputStream;
		protected internal readonly long? max;
		protected internal int rp;
		protected internal int wp;
		protected internal bool end;
//JAVA TO C# CONVERTER NOTE: Fields cannot have the same name as methods:
		protected internal long read_Renamed;

		public CTEBase64InputStream(InputStream src, long? limit)
		{
			this.src = src;
			this.dataOutputStream = new OutputStreamAnonymousInnerClass(this);
			this.max = limit;
		}

		public class OutputStreamAnonymousInnerClass : OutputStream
		{
			private readonly CTEBase64InputStream outerInstance;

			public OutputStreamAnonymousInnerClass(CTEBase64InputStream outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public void write(int b)
			{
				outerInstance.data[outerInstance.wp++] = (byte)b;
			}
		}

		// Pulls a line from the source, decodes it and returns the decoded length.
		// Or returns -1 if there is nothing more to read and nothing was read in this pass.
		public virtual int pullFromSrc()
		{

			if (this.read_Renamed >= this.max.Value)
			{
				return -1;
			}

			int j = 0;
			int c = 0;
			do
			{
				j = src.read();
				/*
				 * RFC2045 All line breaks or other characters not
				 * found in Table 1 must be ignored by decoding software.
				 * https://tools.ietf.org/html/rfc2045#section-6.8
				 * This uses the line brakes to to stop reading data and to decode a chunk.
				 */
				if (j >= 33 || (j == '\r' || j == '\n'))
				{
					if (c >= rawBuf.Length)
					{
						throw new IOException("Content Transfer Encoding, base64 line length > 1024");
					}
					rawBuf[c++] = (byte)j;
					read_Renamed += 1;
				}
				else if (j >= 0)
				{
					read_Renamed += 1;
				}
			} while (j > -1 && c < rawBuf.Length && j != 10 && this.read_Renamed < this.max.Value);

			if (c > 0)
			{
				try
				{
					Base64.decode(rawBuf, 0, c, dataOutputStream);
				}
				catch (Exception ex)
				{
					throw new IOException("Decode Base64 Content-Transfer-Encoding: " + ex);
				}
			}
			else
			{
				if (j == -1)
				{
					return -1;
				}
			}
			return wp;
		}

		public virtual int read()
		{
			// When we have read up to the write pointer (wp) pull some more.
			if (rp == wp)
			{
				rp = 0;
				wp = 0;
				int i = pullFromSrc();
				if (i == -1)
				{
					return i;
				}
			}
			return data[rp++] & 0xFF;
		}

		public virtual void close()
		{
			src.close();
		}
	}

}
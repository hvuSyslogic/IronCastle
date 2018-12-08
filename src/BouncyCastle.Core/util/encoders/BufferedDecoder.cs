using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.util.encoders
{

	/// <summary>
	/// A buffering class to allow translation from one format to another to
	/// be done in discrete chunks.
	/// </summary>
	public class BufferedDecoder
	{
		protected internal byte[] buf;
		protected internal int bufOff;

		protected internal Translator translator;

		/// <param name="translator"> the translator to use. </param>
		/// <param name="bufSize"> amount of input to buffer for each chunk. </param>
		public BufferedDecoder(Translator translator, int bufSize)
		{
			this.translator = translator;

			if ((bufSize % translator.getEncodedBlockSize()) != 0)
			{
				throw new IllegalArgumentException("buffer size not multiple of input block size");
			}

			buf = new byte[bufSize];
			bufOff = 0;
		}

		public virtual int processByte(byte @in, byte[] @out, int outOff)
		{
			int resultLen = 0;

			buf[bufOff++] = @in;

			if (bufOff == buf.Length)
			{
				resultLen = translator.decode(buf, 0, buf.Length, @out, outOff);
				bufOff = 0;
			}

			return resultLen;
		}

		public virtual int processBytes(byte[] @in, int inOff, int len, byte[] @out, int outOff)
		{
			if (len < 0)
			{
				throw new IllegalArgumentException("Can't have a negative input length!");
			}

			int resultLen = 0;
			int gapLen = buf.Length - bufOff;

			if (len > gapLen)
			{
				JavaSystem.arraycopy(@in, inOff, buf, bufOff, gapLen);

				resultLen += translator.decode(buf, 0, buf.Length, @out, outOff);

				bufOff = 0;

				len -= gapLen;
				inOff += gapLen;
				outOff += resultLen;

				int chunkSize = len - (len % buf.Length);

				resultLen += translator.decode(@in, inOff, chunkSize, @out, outOff);

				len -= chunkSize;
				inOff += chunkSize;
			}

			if (len != 0)
			{
				JavaSystem.arraycopy(@in, inOff, buf, bufOff, len);

				bufOff += len;
			}

			return resultLen;
		}
	}

}
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.asn1
{

	public class IndefiniteLengthInputStream : LimitedInputStream
	{
		private int _b1;
		private int _b2;
		private bool _eofReached = false;
		private bool _eofOn00 = true;

		public IndefiniteLengthInputStream(InputStream @in, int limit) : base(@in, limit)
		{

			_b1 = @in.read();
			_b2 = @in.read();

			if (_b2 < 0)
			{
				// Corrupted stream
				throw new EOFException();
			}

			checkForEof();
		}

		public virtual void setEofOn00(bool eofOn00)
		{
			_eofOn00 = eofOn00;
			checkForEof();
		}

		private bool checkForEof()
		{
			if (!_eofReached && _eofOn00 && (_b1 == 0x00 && _b2 == 0x00))
			{
				_eofReached = true;
				setParentEofDetect(true);
			}
			return _eofReached;
		}

		public virtual int read(byte[] b, int off, int len)
		{
			// Only use this optimisation if we aren't checking for 00
			if (_eofOn00 || len < 3)
			{
				return base.read(b, off, len);
			}

			if (_eofReached)
			{
				return -1;
			}

			int numRead = _in.read(b, off + 2, len - 2);

			if (numRead < 0)
			{
				// Corrupted stream
				throw new EOFException();
			}

			b[off] = (byte)_b1;
			b[off + 1] = (byte)_b2;

			_b1 = _in.read();
			_b2 = _in.read();

			if (_b2 < 0)
			{
				// Corrupted stream
				throw new EOFException();
			}

			return numRead + 2;
		}

		public virtual int read()
		{
			if (checkForEof())
			{
				return -1;
			}

			int b = _in.read();

			if (b < 0)
			{
				// Corrupted stream
				throw new EOFException();
			}

			int v = _b1;

			_b1 = _b2;
			_b2 = b;

			return v;
		}
	}

}
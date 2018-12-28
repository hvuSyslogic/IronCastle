using System;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1
{

	using Streams = org.bouncycastle.util.io.Streams;

	/// <summary>
	/// Parse data stream of expected ASN.1 data expecting definite-length encoding..
	/// </summary>
	public class DefiniteLengthInputStream : LimitedInputStream
	{
		private static readonly byte[] EMPTY_BYTES = new byte[0];

		private readonly int _originalLength;
		private int _remaining;

		public DefiniteLengthInputStream(InputStream @in, int length) : base(@in, length)
		{

			if (length < 0)
			{
				throw new IllegalArgumentException("negative lengths not allowed");
			}

			this._originalLength = length;
			this._remaining = length;

			if (length == 0)
			{
				setParentEofDetect(true);
			}
		}

		public override int getRemaining()
		{
			return _remaining;
		}

		public override int read()
		{
			if (_remaining == 0)
			{
				return -1;
			}

			int b = _in.read();

			if (b < 0)
			{
				throw new EOFException("DEF length " + _originalLength + " object truncated by " + _remaining);
			}

			if (--_remaining == 0)
			{
				setParentEofDetect(true);
			}

			return b;
		}

		public override int read(byte[] buf, int off, int len)
		{
			if (_remaining == 0)
			{
				return -1;
			}

			int toRead = Math.Min(len, _remaining);
			int numRead = _in.read(buf, off, toRead);

			if (numRead < 0)
			{
				throw new EOFException("DEF length " + _originalLength + " object truncated by " + _remaining);
			}

			if ((_remaining -= numRead) == 0)
			{
				setParentEofDetect(true);
			}

			return numRead;
		}

		public virtual byte[] toByteArray()
		{
			if (_remaining == 0)
			{
				return EMPTY_BYTES;
			}

			byte[] bytes = new byte[_remaining];
			if ((_remaining -= Streams.readFully(_in, bytes)) != 0)
			{
				throw new EOFException("DEF length " + _originalLength + " object truncated by " + _remaining);
			}
			setParentEofDetect(true);
			return bytes;
		}
	}

}
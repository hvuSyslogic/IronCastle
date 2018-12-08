using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// Internal use stream that allows reading of a limited number of bytes from a wrapped stream.
	/// </summary>
	public abstract class LimitedInputStream : InputStream
	{
		protected internal readonly InputStream _in;
		private int _limit;

		public LimitedInputStream(InputStream @in, int limit)
		{
			this._in = @in;
			this._limit = limit;
		}

		public virtual int getRemaining()
		{
			// TODO: maybe one day this can become more accurate
			return _limit;
		}

		public virtual void setParentEofDetect(bool on)
		{
			if (_in is IndefiniteLengthInputStream)
			{
				((IndefiniteLengthInputStream)_in).setEofOn00(on);
			}
		}
	}

}
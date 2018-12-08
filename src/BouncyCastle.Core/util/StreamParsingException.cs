using System;

namespace org.bouncycastle.util
{
	public class StreamParsingException : Exception
	{
		internal Exception _e;

		public StreamParsingException(string message, Exception e) : base(message)
		{
			_e = e;
		}

		public virtual Exception getCause()
		{
			return _e;
		}
	}

}
using System;

namespace org.bouncycastle.jce.provider
{
	using ExtException = org.bouncycastle.jce.exception.ExtException;

	public class AnnotatedException : Exception, ExtException
	{
		private Exception _underlyingException;

		public AnnotatedException(string @string, Exception e) : base(@string)
		{

			_underlyingException = e;
		}

		public AnnotatedException(string @string) : this(@string, null)
		{
		}

		public virtual Exception getUnderlyingException()
		{
			return _underlyingException;
		}

		public virtual Exception getCause()
		{
			return _underlyingException;
		}
	}

}
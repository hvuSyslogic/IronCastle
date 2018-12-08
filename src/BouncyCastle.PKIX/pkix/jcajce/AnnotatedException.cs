using System;

namespace org.bouncycastle.pkix.jcajce
{
	public class AnnotatedException : Exception
	{
		private Exception _underlyingException;

		public AnnotatedException(string @string, Exception e) : base(@string)
		{

			_underlyingException = e;
		}

		public AnnotatedException(string @string) : this(@string, null)
		{
		}

		public virtual Exception getCause()
		{
			return _underlyingException;
		}
	}

}
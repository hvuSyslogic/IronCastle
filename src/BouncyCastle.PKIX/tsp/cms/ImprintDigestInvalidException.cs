using System;

namespace org.bouncycastle.tsp.cms
{

	public class ImprintDigestInvalidException : Exception
	{
		private TimeStampToken token;

		public ImprintDigestInvalidException(string message, TimeStampToken token) : base(message)
		{

			this.token = token;
		}

		public virtual TimeStampToken getTimeStampToken()
		{
			return token;
		}
	}

}
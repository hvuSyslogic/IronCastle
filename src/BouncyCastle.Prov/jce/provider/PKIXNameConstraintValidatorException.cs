using System;

namespace org.bouncycastle.jce.provider
{
	public class PKIXNameConstraintValidatorException : Exception
	{
		public PKIXNameConstraintValidatorException(string msg) : base(msg)
		{
		}
	}

}
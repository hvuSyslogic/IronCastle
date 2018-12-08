using System;

namespace org.bouncycastle.asn1.x509
{
	public class NameConstraintValidatorException : Exception
	{
		public NameConstraintValidatorException(string msg) : base(msg)
		{
		}
	}

}
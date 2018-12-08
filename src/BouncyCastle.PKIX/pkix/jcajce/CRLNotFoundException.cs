using System;

namespace org.bouncycastle.pkix.jcajce
{

	public class CRLNotFoundException : CertPathValidatorException
	{
		public CRLNotFoundException(string message) : base(message)
		{
		}

		public CRLNotFoundException(string message, Exception cause) : base(message, cause)
		{
		}
	}

}
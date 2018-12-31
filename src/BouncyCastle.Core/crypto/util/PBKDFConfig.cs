using org.bouncycastle.asn1;

namespace org.bouncycastle.crypto.util
{
	
	/// <summary>
	/// Base class for PBKDF configs.
	/// </summary>
	public abstract class PBKDFConfig
	{
		private readonly ASN1ObjectIdentifier algorithm;

		public PBKDFConfig(ASN1ObjectIdentifier algorithm)
		{
			this.algorithm = algorithm;
		}

		public virtual ASN1ObjectIdentifier getAlgorithm()
		{
			return algorithm;
		}
	}

}
using org.bouncycastle.asn1;

namespace org.bouncycastle.crypto.agreement.kdf
{
	
	public class DHKDFParameters : DerivationParameters
	{
		private ASN1ObjectIdentifier algorithm;
		private int keySize;
		private byte[] z;
		private byte[] extraInfo;

		public DHKDFParameters(ASN1ObjectIdentifier algorithm, int keySize, byte[] z) : this(algorithm, keySize, z, null)
		{
		}

		public DHKDFParameters(ASN1ObjectIdentifier algorithm, int keySize, byte[] z, byte[] extraInfo)
		{
			this.algorithm = algorithm;
			this.keySize = keySize;
			this.z = z;
			this.extraInfo = extraInfo;
		}

		public virtual ASN1ObjectIdentifier getAlgorithm()
		{
			return algorithm;
		}

		public virtual int getKeySize()
		{
			return keySize;
		}

		public virtual byte[] getZ()
		{
			return z;
		}

		public virtual byte[] getExtraInfo()
		{
			return extraInfo;
		}
	}

}
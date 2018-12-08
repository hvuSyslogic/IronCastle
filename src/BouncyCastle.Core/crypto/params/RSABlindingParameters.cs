using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.@params
{

	public class RSABlindingParameters : CipherParameters
	{
		private RSAKeyParameters publicKey;
		private BigInteger blindingFactor;

		public RSABlindingParameters(RSAKeyParameters publicKey, BigInteger blindingFactor)
		{
			if (publicKey is RSAPrivateCrtKeyParameters)
			{
				throw new IllegalArgumentException("RSA parameters should be for a public key");
			}

			this.publicKey = publicKey;
			this.blindingFactor = blindingFactor;
		}

		public virtual RSAKeyParameters getPublicKey()
		{
			return publicKey;
		}

		public virtual BigInteger getBlindingFactor()
		{
			return blindingFactor;
		}
	}

}
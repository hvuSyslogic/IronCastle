using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.@params
{

	public class RSAKeyGenerationParameters : KeyGenerationParameters
	{
		private BigInteger publicExponent;
		private int certainty;

		public RSAKeyGenerationParameters(BigInteger publicExponent, SecureRandom random, int strength, int certainty) : base(random, strength)
		{

			if (strength < 12)
			{
				throw new IllegalArgumentException("key strength too small");
			}

			//
			// public exponent cannot be even
			//
			if (!publicExponent.testBit(0))
			{
					throw new IllegalArgumentException("public exponent cannot be even");
			}

			this.publicExponent = publicExponent;
			this.certainty = certainty;
		}

		public virtual BigInteger getPublicExponent()
		{
			return publicExponent;
		}

		public virtual int getCertainty()
		{
			return certainty;
		}
	}

}
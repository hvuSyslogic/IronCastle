using BouncyCastle.Core;
using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.math.ec;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.generators
{

										
	public class ECKeyPairGenerator : AsymmetricCipherKeyPairGenerator, ECConstants
	{
		internal ECDomainParameters @params;
		internal SecureRandom random;

		public virtual void init(KeyGenerationParameters param)
		{
			ECKeyGenerationParameters ecP = (ECKeyGenerationParameters)param;

			this.random = ecP.getRandom();
			this.@params = ecP.getDomainParameters();

			if (this.random == null)
			{
				this.random = CryptoServicesRegistrar.getSecureRandom();
			}
		}

		/// <summary>
		/// Given the domain parameters this routine generates an EC key
		/// pair in accordance with X9.62 section 5.2.1 pages 26, 27.
		/// </summary>
		public virtual AsymmetricCipherKeyPair generateKeyPair()
		{
			BigInteger n = @params.getN();
			int nBitLength = n.bitLength();
			int minWeight = (int)((uint)nBitLength >> 2);

			BigInteger d;
			for (;;)
			{
				d = BigIntegers.createRandomBigInteger(nBitLength, random);

				if (d.compareTo(ECConstants_Fields.TWO) < 0 || (d.compareTo(n) >= 0))
				{
					continue;
				}

				if (WNafUtil.getNafWeight(d) < minWeight)
				{
					continue;
				}

				break;
			}

			ECPoint Q = createBasePointMultiplier().multiply(@params.getG(), d);

			return new AsymmetricCipherKeyPair(new ECPublicKeyParameters(Q, @params), new ECPrivateKeyParameters(d, @params));
		}

		public virtual ECMultiplier createBasePointMultiplier()
		{
			return new FixedPointCombMultiplier();
		}
	}

}
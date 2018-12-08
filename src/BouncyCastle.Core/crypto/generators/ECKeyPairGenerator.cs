using BouncyCastle.Core.Port;
using org.bouncycastle.math.ec;

namespace org.bouncycastle.crypto.generators
{

	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using ECKeyGenerationParameters = org.bouncycastle.crypto.@params.ECKeyGenerationParameters;
	using ECPrivateKeyParameters = org.bouncycastle.crypto.@params.ECPrivateKeyParameters;
	using ECPublicKeyParameters = org.bouncycastle.crypto.@params.ECPublicKeyParameters;
	using ECConstants = org.bouncycastle.math.ec.ECConstants;
	using ECMultiplier = org.bouncycastle.math.ec.ECMultiplier;
	using ECPoint = org.bouncycastle.math.ec.ECPoint;
	using FixedPointCombMultiplier = org.bouncycastle.math.ec.FixedPointCombMultiplier;
	using WNafUtil = org.bouncycastle.math.ec.WNafUtil;
	using BigIntegers = org.bouncycastle.util.BigIntegers;

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
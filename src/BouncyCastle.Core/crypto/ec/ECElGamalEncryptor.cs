using BouncyCastle.Core;
using BouncyCastle.Core.Port;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.ec
{

	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using ECPublicKeyParameters = org.bouncycastle.crypto.@params.ECPublicKeyParameters;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using ECAlgorithms = org.bouncycastle.math.ec.ECAlgorithms;
	using ECMultiplier = org.bouncycastle.math.ec.ECMultiplier;
	using ECPoint = org.bouncycastle.math.ec.ECPoint;
	using FixedPointCombMultiplier = org.bouncycastle.math.ec.FixedPointCombMultiplier;

	/// <summary>
	/// this does your basic ElGamal encryption algorithm using EC
	/// </summary>
	public class ECElGamalEncryptor : ECEncryptor
	{
		private ECPublicKeyParameters key;
		private SecureRandom random;

		/// <summary>
		/// initialise the encryptor.
		/// </summary>
		/// <param name="param"> the necessary EC key parameters. </param>
		public virtual void init(CipherParameters param)
		{
			if (param is ParametersWithRandom)
			{
				ParametersWithRandom p = (ParametersWithRandom)param;

				if (!(p.getParameters() is ECPublicKeyParameters))
				{
					throw new IllegalArgumentException("ECPublicKeyParameters are required for encryption.");
				}
				this.key = (ECPublicKeyParameters)p.getParameters();
				this.random = p.getRandom();
			}
			else
			{
				if (!(param is ECPublicKeyParameters))
				{
					throw new IllegalArgumentException("ECPublicKeyParameters are required for encryption.");
				}

				this.key = (ECPublicKeyParameters)param;
				this.random = CryptoServicesRegistrar.getSecureRandom();
			}
		}

		/// <summary>
		/// Process a single EC point using the basic ElGamal algorithm.
		/// </summary>
		/// <param name="point"> the EC point to process. </param>
		/// <returns> the result of the Elgamal process. </returns>
		public virtual ECPair encrypt(ECPoint point)
		{
			if (key == null)
			{
				throw new IllegalStateException("ECElGamalEncryptor not initialised");
			}

			ECDomainParameters ec = key.getParameters();
			BigInteger k = ECUtil.generateK(ec.getN(), random);

			ECMultiplier basePointMultiplier = createBasePointMultiplier();

			ECPoint[] gamma_phi = new ECPoint[]{basePointMultiplier.multiply(ec.getG(), k), key.getQ().multiply(k).add(ECAlgorithms.cleanPoint(ec.getCurve(), point))};

			ec.getCurve().normalizeAll(gamma_phi);

			return new ECPair(gamma_phi[0], gamma_phi[1]);
		}

		public virtual ECMultiplier createBasePointMultiplier()
		{
			return new FixedPointCombMultiplier();
		}
	}

}
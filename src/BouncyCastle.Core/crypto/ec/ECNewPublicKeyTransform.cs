using BouncyCastle.Core;
using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.math.ec;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.ec
{

							
	/// <summary>
	/// this does your basic Elgamal encryption algorithm using EC
	/// </summary>
	public class ECNewPublicKeyTransform : ECPairTransform
	{
		private ECPublicKeyParameters key;
		private SecureRandom random;

		/// <summary>
		/// initialise the EC Elgamal engine.
		/// </summary>
		/// <param name="param"> the necessary EC key parameters. </param>
		public virtual void init(CipherParameters param)
		{
			if (param is ParametersWithRandom)
			{
				ParametersWithRandom p = (ParametersWithRandom)param;

				if (!(p.getParameters() is ECPublicKeyParameters))
				{
					throw new IllegalArgumentException("ECPublicKeyParameters are required for new public key transform.");
				}
				this.key = (ECPublicKeyParameters)p.getParameters();
				this.random = p.getRandom();
			}
			else
			{
				if (!(param is ECPublicKeyParameters))
				{
					throw new IllegalArgumentException("ECPublicKeyParameters are required for new public key transform.");
				}

				this.key = (ECPublicKeyParameters)param;
				this.random = CryptoServicesRegistrar.getSecureRandom();
			}
		}

		/// <summary>
		/// Transform an existing cipher text pair using the ElGamal algorithm. Note: the input cipherText will
		/// need to be preserved in order to complete the transformation to the new public key.
		/// </summary>
		/// <param name="cipherText"> the EC point to process. </param>
		/// <returns> returns a new ECPair representing the result of the process. </returns>
		public virtual ECPair transform(ECPair cipherText)
		{
			if (key == null)
			{
				throw new IllegalStateException("ECNewPublicKeyTransform not initialised");
			}

			ECDomainParameters ec = key.getParameters();
			BigInteger n = ec.getN();

			ECMultiplier basePointMultiplier = createBasePointMultiplier();
			BigInteger k = ECUtil.generateK(n, random);

			ECPoint[] gamma_phi = new ECPoint[]{basePointMultiplier.multiply(ec.getG(), k), key.getQ().multiply(k).add(ECAlgorithms.cleanPoint(ec.getCurve(), cipherText.getY()))};

			ec.getCurve().normalizeAll(gamma_phi);

			return new ECPair(gamma_phi[0], gamma_phi[1]);
		}

		public virtual ECMultiplier createBasePointMultiplier()
		{
			return new FixedPointCombMultiplier();
		}
	}

}
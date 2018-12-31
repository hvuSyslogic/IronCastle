using BouncyCastle.Core;
using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.math.ec;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.ec
{

							
	/// <summary>
	/// this transforms the original randomness used for an ElGamal encryption.
	/// </summary>
	public class ECNewRandomnessTransform : ECPairFactorTransform
	{
		private ECPublicKeyParameters key;
		private SecureRandom random;

		private BigInteger lastK;

		/// <summary>
		/// initialise the underlying EC ElGamal engine.
		/// </summary>
		/// <param name="param"> the necessary EC key parameters. </param>
		public virtual void init(CipherParameters param)
		{
			if (param is ParametersWithRandom)
			{
				ParametersWithRandom p = (ParametersWithRandom)param;

				if (!(p.getParameters() is ECPublicKeyParameters))
				{
					throw new IllegalArgumentException("ECPublicKeyParameters are required for new randomness transform.");
				}

				this.key = (ECPublicKeyParameters)p.getParameters();
				this.random = p.getRandom();
			}
			else
			{
				if (!(param is ECPublicKeyParameters))
				{
					throw new IllegalArgumentException("ECPublicKeyParameters are required for new randomness transform.");
				}

				this.key = (ECPublicKeyParameters)param;
				this.random = CryptoServicesRegistrar.getSecureRandom();
			}
		}

		/// <summary>
		/// Transform an existing cipher test pair using the ElGamal algorithm. Note: it is assumed this
		/// transform has been initialised with the same public key that was used to create the original
		/// cipher text.
		/// </summary>
		/// <param name="cipherText"> the EC point to process. </param>
		/// <returns> returns a new ECPair representing the result of the process. </returns>
		public virtual ECPair transform(ECPair cipherText)
		{
			if (key == null)
			{
				throw new IllegalStateException("ECNewRandomnessTransform not initialised");
			}


			ECDomainParameters ec = key.getParameters();
			BigInteger n = ec.getN();

			ECMultiplier basePointMultiplier = createBasePointMultiplier();
			BigInteger k = ECUtil.generateK(n, random);

			ECPoint[] gamma_phi = new ECPoint[]{basePointMultiplier.multiply(ec.getG(), k).add(ECAlgorithms.cleanPoint(ec.getCurve(), cipherText.getX())), key.getQ().multiply(k).add(ECAlgorithms.cleanPoint(ec.getCurve(), cipherText.getY()))};

			ec.getCurve().normalizeAll(gamma_phi);

			lastK = k;

			return new ECPair(gamma_phi[0], gamma_phi[1]);
		}

		/// <summary>
		/// Return the last random value generated for a transform
		/// </summary>
		/// <returns> a BigInteger representing the last random value. </returns>
		public virtual BigInteger getTransformValue()
		{
			return lastK;
		}

		public virtual ECMultiplier createBasePointMultiplier()
		{
			return new FixedPointCombMultiplier();
		}
	}

}
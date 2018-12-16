using BouncyCastle.Core;
using BouncyCastle.Core.Port;
using org.bouncycastle.math.ec;

namespace org.bouncycastle.crypto.signers
{

	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using ECKeyParameters = org.bouncycastle.crypto.@params.ECKeyParameters;
	using ECPrivateKeyParameters = org.bouncycastle.crypto.@params.ECPrivateKeyParameters;
	using ECPublicKeyParameters = org.bouncycastle.crypto.@params.ECPublicKeyParameters;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using ECAlgorithms = org.bouncycastle.math.ec.ECAlgorithms;
	using ECConstants = org.bouncycastle.math.ec.ECConstants;
	using ECMultiplier = org.bouncycastle.math.ec.ECMultiplier;
	using ECPoint = org.bouncycastle.math.ec.ECPoint;
	using FixedPointCombMultiplier = org.bouncycastle.math.ec.FixedPointCombMultiplier;
	using BigIntegers = org.bouncycastle.util.BigIntegers;

	/// <summary>
	/// GOST R 34.10-2012 Signature Algorithm
	/// </summary>
	public class ECGOST3410_2012Signer : DSAExt
	{
		internal ECKeyParameters key;

		internal SecureRandom random;

		public virtual void init(bool forSigning, CipherParameters param)
		{
			if (forSigning)
			{
				if (param is ParametersWithRandom)
				{
					ParametersWithRandom rParam = (ParametersWithRandom)param;

					this.random = rParam.getRandom();
					this.key = (ECPrivateKeyParameters)rParam.getParameters();
				}
				else
				{
					this.random = CryptoServicesRegistrar.getSecureRandom();
					this.key = (ECPrivateKeyParameters)param;
				}
			}
			else
			{
				this.key = (ECPublicKeyParameters)param;
			}
		}

		public virtual BigInteger getOrder()
		{
			return key.getParameters().getN();
		}

		/// <summary>
		/// generate a signature for the given message using the key we were
		/// initialised with. For conventional GOST3410 2012 the message should be a GOST3411 2012
		/// hash of the message of interest.
		/// </summary>
		/// <param name="message"> the message that will be verified later. </param>
		public virtual BigInteger[] generateSignature(byte[] message)
		{
			byte[] mRev = new byte[message.Length]; // conversion is little-endian
			for (int i = 0; i != mRev.Length; i++)
			{
				mRev[i] = message[mRev.Length - 1 - i];
			}
			BigInteger e = new BigInteger(1, mRev);

			ECDomainParameters ec = key.getParameters();
			BigInteger n = ec.getN();
			BigInteger d = ((ECPrivateKeyParameters)key).getD();

			BigInteger r, s;

			ECMultiplier basePointMultiplier = createBasePointMultiplier();

			do // generate s
			{
				BigInteger k;
				do // generate r
				{
					do
					{
						k = BigIntegers.createRandomBigInteger(n.bitLength(), random);
					} while (k.Equals(ECConstants_Fields.ZERO));

					ECPoint p = basePointMultiplier.multiply(ec.getG(), k).normalize();

					r = p.getAffineXCoord().toBigInteger().mod(n);
				} while (r.Equals(ECConstants_Fields.ZERO));

				s = (k.multiply(e)).add(d.multiply(r)).mod(n);
			} while (s.Equals(ECConstants_Fields.ZERO));

			return new BigInteger[]{r, s};
		}

		/// <summary>
		/// return true if the value r and s represent a GOST3410 2012 signature for
		/// the passed in message (for standard GOST3410 2012 the message should be
		/// a GOST3411 2012 hash of the real message to be verified).
		/// </summary>
		public virtual bool verifySignature(byte[] message, BigInteger r, BigInteger s)
		{


			byte[] mRev = new byte[message.Length]; // conversion is little-endian
			for (int i = 0; i != mRev.Length; i++)
			{
				mRev[i] = message[mRev.Length - 1 - i];
			}
			BigInteger e = new BigInteger(1, mRev);
			BigInteger n = key.getParameters().getN();

			// r in the range [1,n-1]
			if (r.compareTo(ECConstants_Fields.ONE) < 0 || r.compareTo(n) >= 0)
			{
				return false;
			}

			// s in the range [1,n-1]
			if (s.compareTo(ECConstants_Fields.ONE) < 0 || s.compareTo(n) >= 0)
			{
				return false;
			}

			BigInteger v = e.modInverse(n);

			BigInteger z1 = s.multiply(v).mod(n);
			BigInteger z2 = (n.subtract(r)).multiply(v).mod(n);

			ECPoint G = key.getParameters().getG(); // P
			ECPoint Q = ((ECPublicKeyParameters)key).getQ();

			ECPoint point = ECAlgorithms.sumOfTwoMultiplies(G, z1, Q, z2).normalize();

			// components must be bogus.
			if (point.isInfinity())
			{
				return false;
			}

			BigInteger R = point.getAffineXCoord().toBigInteger().mod(n);

			return R.Equals(r);
		}

		public virtual ECMultiplier createBasePointMultiplier()
		{
			return new FixedPointCombMultiplier();
		}
	}

}
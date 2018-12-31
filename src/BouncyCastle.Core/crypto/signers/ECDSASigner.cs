using BouncyCastle.Core;
using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.math.ec;

namespace org.bouncycastle.crypto.signers
{

												
	/// <summary>
	/// EC-DSA as described in X9.62
	/// </summary>
	public class ECDSASigner : ECConstants, DSAExt
	{
		private readonly DSAKCalculator kCalculator;

		private ECKeyParameters key;
		private SecureRandom random;

		/// <summary>
		/// Default configuration, random K values.
		/// </summary>
		public ECDSASigner()
		{
			this.kCalculator = new RandomDSAKCalculator();
		}

		/// <summary>
		/// Configuration with an alternate, possibly deterministic calculator of K.
		/// </summary>
		/// <param name="kCalculator"> a K value calculator. </param>
		public ECDSASigner(DSAKCalculator kCalculator)
		{
			this.kCalculator = kCalculator;
		}

		public virtual void init(bool forSigning, CipherParameters param)
		{
			SecureRandom providedRandom = null;

			if (forSigning)
			{
				if (param is ParametersWithRandom)
				{
					ParametersWithRandom rParam = (ParametersWithRandom)param;

					this.key = (ECPrivateKeyParameters)rParam.getParameters();
					providedRandom = rParam.getRandom();
				}
				else
				{
					this.key = (ECPrivateKeyParameters)param;
				}
			}
			else
			{
				this.key = (ECPublicKeyParameters)param;
			}

			this.random = initSecureRandom(forSigning && !kCalculator.isDeterministic(), providedRandom);
		}

		public virtual BigInteger getOrder()
		{
			return key.getParameters().getN();
		}

		// 5.3 pg 28
		/// <summary>
		/// generate a signature for the given message using the key we were
		/// initialised with. For conventional DSA the message should be a SHA-1
		/// hash of the message of interest.
		/// </summary>
		/// <param name="message"> the message that will be verified later. </param>
		public virtual BigInteger[] generateSignature(byte[] message)
		{
			ECDomainParameters ec = key.getParameters();
			BigInteger n = ec.getN();
			BigInteger e = calculateE(n, message);
			BigInteger d = ((ECPrivateKeyParameters)key).getD();

			if (kCalculator.isDeterministic())
			{
				kCalculator.init(n, d, message);
			}
			else
			{
				kCalculator.init(n, random);
			}

			BigInteger r, s;

			ECMultiplier basePointMultiplier = createBasePointMultiplier();

			// 5.3.2
			do // generate s
			{
				BigInteger k;
				do // generate r
				{
					k = kCalculator.nextK();

					ECPoint p = basePointMultiplier.multiply(ec.getG(), k).normalize();

					// 5.3.3
					r = p.getAffineXCoord().toBigInteger().mod(n);
				} while (r.Equals(ECConstants_Fields.ZERO));

				s = k.modInverse(n).multiply(e.add(d.multiply(r))).mod(n);
			} while (s.Equals(ECConstants_Fields.ZERO));

			return new BigInteger[]{r, s};
		}

		// 5.4 pg 29
		/// <summary>
		/// return true if the value r and s represent a DSA signature for
		/// the passed in message (for standard DSA the message should be
		/// a SHA-1 hash of the real message to be verified).
		/// </summary>
		public virtual bool verifySignature(byte[] message, BigInteger r, BigInteger s)
		{
			ECDomainParameters ec = key.getParameters();
			BigInteger n = ec.getN();
			BigInteger e = calculateE(n, message);

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

			BigInteger c = s.modInverse(n);

			BigInteger u1 = e.multiply(c).mod(n);
			BigInteger u2 = r.multiply(c).mod(n);

			ECPoint G = ec.getG();
			ECPoint Q = ((ECPublicKeyParameters)key).getQ();

			ECPoint point = ECAlgorithms.sumOfTwoMultiplies(G, u1, Q, u2);

			// components must be bogus.
			if (point.isInfinity())
			{
				return false;
			}

			/*
			 * If possible, avoid normalizing the point (to save a modular inversion in the curve field).
			 * 
			 * There are ~cofactor elements of the curve field that reduce (modulo the group order) to 'r'.
			 * If the cofactor is known and small, we generate those possible field values and project each
			 * of them to the same "denominator" (depending on the particular projective coordinates in use)
			 * as the calculated point.X. If any of the projected values matches point.X, then we have:
			 *     (point.X / Denominator mod p) mod n == r
			 * as required, and verification succeeds.
			 * 
			 * Based on an original idea by Gregory Maxwell (https://github.com/gmaxwell), as implemented in
			 * the libsecp256k1 project (https://github.com/bitcoin/secp256k1).
			 */
			ECCurve curve = point.getCurve();
			if (curve != null)
			{
				BigInteger cofactor = curve.getCofactor();
				if (cofactor != null && cofactor.compareTo(ECConstants_Fields.EIGHT) <= 0)
				{
					ECFieldElement D = getDenominator(curve.getCoordinateSystem(), point);
					if (D != null && !D.isZero())
					{
						ECFieldElement X = point.getXCoord();
						while (curve.isValidFieldElement(r))
						{
							ECFieldElement R = curve.fromBigInteger(r).multiply(D);
							if (R.Equals(X))
							{
								return true;
							}
							r = r.add(n);
						}
						return false;
					}
				}
			}

			BigInteger v = point.normalize().getAffineXCoord().toBigInteger().mod(n);
			return v.Equals(r);
		}

		public virtual BigInteger calculateE(BigInteger n, byte[] message)
		{
			int log2n = n.bitLength();
			int messageBitLength = message.Length * 8;

			BigInteger e = new BigInteger(1, message);
			if (log2n < messageBitLength)
			{
				e = e.shiftRight(messageBitLength - log2n);
			}
			return e;
		}

		public virtual ECMultiplier createBasePointMultiplier()
		{
			return new FixedPointCombMultiplier();
		}

		public virtual ECFieldElement getDenominator(int coordinateSystem, ECPoint p)
		{
			switch (coordinateSystem)
			{
			case ECCurve.COORD_HOMOGENEOUS:
			case ECCurve.COORD_LAMBDA_PROJECTIVE:
			case ECCurve.COORD_SKEWED:
				return p.getZCoord(0);
			case ECCurve.COORD_JACOBIAN:
			case ECCurve.COORD_JACOBIAN_CHUDNOVSKY:
			case ECCurve.COORD_JACOBIAN_MODIFIED:
				return p.getZCoord(0).square();
			default:
				return null;
			}
		}

		public virtual SecureRandom initSecureRandom(bool needed, SecureRandom provided)
		{
			return !needed ? null : (provided != null) ? provided : CryptoServicesRegistrar.getSecureRandom();
		}
	}

}
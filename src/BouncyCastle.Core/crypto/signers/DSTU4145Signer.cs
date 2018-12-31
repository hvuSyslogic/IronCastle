﻿using BouncyCastle.Core;
using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.math.ec;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.signers
{

													
	/// <summary>
	/// DSTU 4145-2002
	/// <para>
	/// National Ukrainian standard of digital signature based on elliptic curves (DSTU 4145-2002).
	/// </para>
	/// </summary>
	public class DSTU4145Signer : DSAExt
	{
		private static readonly BigInteger ONE = BigInteger.valueOf(1);

		private ECKeyParameters key;
		private SecureRandom random;

		public virtual void init(bool forSigning, CipherParameters param)
		{
			if (forSigning)
			{
				if (param is ParametersWithRandom)
				{
					ParametersWithRandom rParam = (ParametersWithRandom)param;

					this.random = rParam.getRandom();
					param = rParam.getParameters();
				}
				else
				{
					this.random = CryptoServicesRegistrar.getSecureRandom();
				}

				this.key = (ECPrivateKeyParameters)param;
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

		public virtual BigInteger[] generateSignature(byte[] message)
		{
			ECDomainParameters ec = key.getParameters();

			ECCurve curve = ec.getCurve();

			ECFieldElement h = hash2FieldElement(curve, message);
			if (h.isZero())
			{
				h = curve.fromBigInteger(ONE);
			}

			BigInteger n = ec.getN();
			BigInteger e, r, s;
			ECFieldElement Fe, y;

			BigInteger d = ((ECPrivateKeyParameters)key).getD();

			ECMultiplier basePointMultiplier = createBasePointMultiplier();

			do
			{
				do
				{
					do
					{
						e = generateRandomInteger(n, random);
						Fe = basePointMultiplier.multiply(ec.getG(), e).normalize().getAffineXCoord();
					} while (Fe.isZero());

					y = h.multiply(Fe);
					r = fieldElement2Integer(n, y);
				} while (r.signum() == 0);

				s = r.multiply(d).add(e).mod(n);
			} while (s.signum() == 0);

			return new BigInteger[]{r, s};
		}

		public virtual bool verifySignature(byte[] message, BigInteger r, BigInteger s)
		{
			if (r.signum() <= 0 || s.signum() <= 0)
			{
				return false;
			}

			ECDomainParameters parameters = key.getParameters();

			BigInteger n = parameters.getN();
			if (r.compareTo(n) >= 0 || s.compareTo(n) >= 0)
			{
				return false;
			}

			ECCurve curve = parameters.getCurve();

			ECFieldElement h = hash2FieldElement(curve, message);
			if (h.isZero())
			{
				h = curve.fromBigInteger(ONE);
			}

			ECPoint R = ECAlgorithms.sumOfTwoMultiplies(parameters.getG(), s, ((ECPublicKeyParameters)key).getQ(), r).normalize();

			// components must be bogus.
			if (R.isInfinity())
			{
				return false;
			}

			ECFieldElement y = h.multiply(R.getAffineXCoord());
			return fieldElement2Integer(n, y).compareTo(r) == 0;
		}

		public virtual ECMultiplier createBasePointMultiplier()
		{
			return new FixedPointCombMultiplier();
		}

		/// <summary>
		/// Generates random integer such, than its bit length is less than that of n
		/// </summary>
		private static BigInteger generateRandomInteger(BigInteger n, SecureRandom random)
		{
			return BigIntegers.createRandomBigInteger(n.bitLength() - 1, random);
		}

		private static ECFieldElement hash2FieldElement(ECCurve curve, byte[] hash)
		{
			byte[] data = Arrays.reverse(hash);
			return curve.fromBigInteger(truncate(new BigInteger(1, data), curve.getFieldSize()));
		}

		private static BigInteger fieldElement2Integer(BigInteger n, ECFieldElement fe)
		{
			return truncate(fe.toBigInteger(), n.bitLength() - 1);
		}

		private static BigInteger truncate(BigInteger x, int bitLength)
		{
			if (x.bitLength() > bitLength)
			{
				x = x.mod(ONE.shiftLeft(bitLength));
			}
			return x;
		}
	}

}
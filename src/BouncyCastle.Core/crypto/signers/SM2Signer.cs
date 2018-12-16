using org.bouncycastle.math.ec;

using System;
using BouncyCastle.Core;
using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.signers
{

	using SM3Digest = org.bouncycastle.crypto.digests.SM3Digest;
	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using ECKeyParameters = org.bouncycastle.crypto.@params.ECKeyParameters;
	using ECPrivateKeyParameters = org.bouncycastle.crypto.@params.ECPrivateKeyParameters;
	using ECPublicKeyParameters = org.bouncycastle.crypto.@params.ECPublicKeyParameters;
	using ParametersWithID = org.bouncycastle.crypto.@params.ParametersWithID;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using ECAlgorithms = org.bouncycastle.math.ec.ECAlgorithms;
	using ECConstants = org.bouncycastle.math.ec.ECConstants;
	using ECFieldElement = org.bouncycastle.math.ec.ECFieldElement;
	using ECMultiplier = org.bouncycastle.math.ec.ECMultiplier;
	using ECPoint = org.bouncycastle.math.ec.ECPoint;
	using FixedPointCombMultiplier = org.bouncycastle.math.ec.FixedPointCombMultiplier;
	using Hex = org.bouncycastle.util.encoders.Hex;

	/// <summary>
	/// The SM2 Digital Signature algorithm.
	/// </summary>
	public class SM2Signer : Signer, ECConstants
	{
		private readonly DSAKCalculator kCalculator = new RandomDSAKCalculator();
		private readonly SM3Digest digest = new SM3Digest();
		private readonly DSAEncoding encoding;

		private ECDomainParameters ecParams;
		private ECPoint pubPoint;
		private ECKeyParameters ecKey;
		private byte[] z;

		public SM2Signer() : this(StandardDSAEncoding.INSTANCE)
		{
		}

		public SM2Signer(DSAEncoding encoding)
		{
			this.encoding = encoding;
		}

		public virtual void init(bool forSigning, CipherParameters param)
		{
			CipherParameters baseParam;
			byte[] userID;

			if (param is ParametersWithID)
			{
				baseParam = ((ParametersWithID)param).getParameters();
				userID = ((ParametersWithID)param).getID();
			}
			else
			{
				baseParam = param;
				userID = Hex.decode("31323334353637383132333435363738"); // the default value
			}

			if (forSigning)
			{
				if (baseParam is ParametersWithRandom)
				{
					ParametersWithRandom rParam = (ParametersWithRandom)baseParam;

					ecKey = (ECKeyParameters)rParam.getParameters();
					ecParams = ecKey.getParameters();
					kCalculator.init(ecParams.getN(), rParam.getRandom());
				}
				else
				{
					ecKey = (ECKeyParameters)baseParam;
					ecParams = ecKey.getParameters();
					kCalculator.init(ecParams.getN(), CryptoServicesRegistrar.getSecureRandom());
				}
				pubPoint = createBasePointMultiplier().multiply(ecParams.getG(), ((ECPrivateKeyParameters)ecKey).getD()).normalize();
			}
			else
			{
				ecKey = (ECKeyParameters)baseParam;
				ecParams = ecKey.getParameters();
				pubPoint = ((ECPublicKeyParameters)ecKey).getQ();
			}

			z = getZ(userID);

			digest.update(z, 0, z.Length);
		}

		public virtual void update(byte b)
		{
			digest.update(b);
		}

		public virtual void update(byte[] @in, int off, int len)
		{
			digest.update(@in, off, len);
		}

		public virtual bool verifySignature(byte[] signature)
		{
			try
			{
				BigInteger[] rs = encoding.decode(ecParams.getN(), signature);

				return verifySignature(rs[0], rs[1]);
			}
			catch (Exception)
			{
			}

			return false;
		}

		public virtual void reset()
		{
			digest.reset();

			if (z != null)
			{
				digest.update(z, 0, z.Length);
			}
		}

		public virtual byte[] generateSignature()
		{
			byte[] eHash = digestDoFinal();

			BigInteger n = ecParams.getN();
			BigInteger e = calculateE(eHash);
			BigInteger d = ((ECPrivateKeyParameters)ecKey).getD();

			BigInteger r, s;

			ECMultiplier basePointMultiplier = createBasePointMultiplier();

			// 5.2.1 Draft RFC:  SM2 Public Key Algorithms
			do // generate s
			{
				BigInteger k;
				do // generate r
				{
					// A3
					k = kCalculator.nextK();

					// A4
					ECPoint p = basePointMultiplier.multiply(ecParams.getG(), k).normalize();

					// A5
					r = e.add(p.getAffineXCoord().toBigInteger()).mod(n);
				} while (r.Equals(ECConstants_Fields.ZERO) || r.add(k).Equals(n));

				// A6
				BigInteger dPlus1ModN = d.add(ECConstants_Fields.ONE).modInverse(n);

				s = k.subtract(r.multiply(d)).mod(n);
				s = dPlus1ModN.multiply(s).mod(n);
			} while (s.Equals(ECConstants_Fields.ZERO));

			// A7
			try
			{
				return encoding.encode(ecParams.getN(), r, s);
			}
			catch (Exception ex)
			{
				throw new CryptoException("unable to encode signature: " + ex.Message, ex);
			}
		}

		private bool verifySignature(BigInteger r, BigInteger s)
		{
			BigInteger n = ecParams.getN();

			// 5.3.1 Draft RFC:  SM2 Public Key Algorithms
			// B1
			if (r.compareTo(ECConstants_Fields.ONE) < 0 || r.compareTo(n) >= 0)
			{
				return false;
			}

			// B2
			if (s.compareTo(ECConstants_Fields.ONE) < 0 || s.compareTo(n) >= 0)
			{
				return false;
			}

			// B3
			byte[] eHash = digestDoFinal();

			// B4
			BigInteger e = calculateE(eHash);

			// B5
			BigInteger t = r.add(s).mod(n);
			if (t.Equals(ECConstants_Fields.ZERO))
			{
				return false;
			}

			// B6
			ECPoint q = ((ECPublicKeyParameters)ecKey).getQ();
			ECPoint x1y1 = ECAlgorithms.sumOfTwoMultiplies(ecParams.getG(), s, q, t).normalize();
			if (x1y1.isInfinity())
			{
				return false;
			}

			// B7
			BigInteger expectedR = e.add(x1y1.getAffineXCoord().toBigInteger()).mod(n);

			return expectedR.Equals(r);
		}

		private byte[] digestDoFinal()
		{
			byte[] result = new byte[digest.getDigestSize()];
			digest.doFinal(result, 0);

			reset();

			return result;
		}

		private byte[] getZ(byte[] userID)
		{
			digest.reset();

			addUserID(digest, userID);

			addFieldElement(digest, ecParams.getCurve().getA());
			addFieldElement(digest, ecParams.getCurve().getB());
			addFieldElement(digest, ecParams.getG().getAffineXCoord());
			addFieldElement(digest, ecParams.getG().getAffineYCoord());
			addFieldElement(digest, pubPoint.getAffineXCoord());
			addFieldElement(digest, pubPoint.getAffineYCoord());

			byte[] result = new byte[digest.getDigestSize()];

			digest.doFinal(result, 0);

			return result;
		}

		private void addUserID(Digest digest, byte[] userID)
		{
			int len = userID.Length * 8;
			digest.update(unchecked((byte)(len >> 8 & 0xFF)));
			digest.update(unchecked((byte)(len & 0xFF)));
			digest.update(userID, 0, userID.Length);
		}

		private void addFieldElement(Digest digest, ECFieldElement v)
		{
			byte[] p = v.getEncoded();
			digest.update(p, 0, p.Length);
		}

		public virtual ECMultiplier createBasePointMultiplier()
		{
			return new FixedPointCombMultiplier();
		}

		public virtual BigInteger calculateE(byte[] message)
		{
			return new BigInteger(1, message);
		}
	}

}
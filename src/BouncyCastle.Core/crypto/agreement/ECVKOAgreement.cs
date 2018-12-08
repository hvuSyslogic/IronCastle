using BouncyCastle.Core.Port;
using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.agreement
{

	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using ECPrivateKeyParameters = org.bouncycastle.crypto.@params.ECPrivateKeyParameters;
	using ECPublicKeyParameters = org.bouncycastle.crypto.@params.ECPublicKeyParameters;
	using ParametersWithUKM = org.bouncycastle.crypto.@params.ParametersWithUKM;
	using ECAlgorithms = org.bouncycastle.math.ec.ECAlgorithms;
	using ECPoint = org.bouncycastle.math.ec.ECPoint;
	using BigIntegers = org.bouncycastle.util.BigIntegers;

	/// <summary>
	/// GOST VKO key agreement class - RFC 7836 Section 4.3
	/// </summary>
	public class ECVKOAgreement
	{
		private readonly Digest digest;

		private ECPrivateKeyParameters key;
		private BigInteger ukm;

		public ECVKOAgreement(Digest digest)
		{
			this.digest = digest;
		}

		public virtual void init(CipherParameters key)
		{
			ParametersWithUKM p = (ParametersWithUKM)key;

			this.key = (ECPrivateKeyParameters)p.getParameters();
			this.ukm = toInteger(p.getUKM());
		}

		public virtual int getFieldSize()
		{
			return (key.getParameters().getCurve().getFieldSize() + 7) / 8;
		}

		public virtual byte[] calculateAgreement(CipherParameters pubKey)
		{
			ECPublicKeyParameters pub = (ECPublicKeyParameters)pubKey;
			ECDomainParameters @params = key.getParameters();
			if (!@params.Equals(pub.getParameters()))
			{
				throw new IllegalStateException("ECVKO public key has wrong domain parameters");
			}

			BigInteger hd = @params.getH().multiply(ukm).multiply(key.getD()).mod(@params.getN());

			// Always perform calculations on the exact curve specified by our private key's parameters
			ECPoint pubPoint = ECAlgorithms.cleanPoint(@params.getCurve(), pub.getQ());
			if (pubPoint.isInfinity())
			{
				throw new IllegalStateException("Infinity is not a valid public key for ECDHC");
			}

			ECPoint P = pubPoint.multiply(hd).normalize();

			if (P.isInfinity())
			{
				throw new IllegalStateException("Infinity is not a valid agreement value for ECVKO");
			}

			return fromPoint(P);
		}

		private static BigInteger toInteger(byte[] ukm)
		{
			byte[] v = new byte[ukm.Length];

			for (int i = 0; i != v.Length; i++)
			{
				v[i] = ukm[ukm.Length - i - 1];
			}

			return new BigInteger(1, v);
		}

		private byte[] fromPoint(ECPoint v)
		{
			BigInteger bX = v.getAffineXCoord().toBigInteger();
			BigInteger bY = v.getAffineYCoord().toBigInteger();

			int size;
			if (bX.toByteArray().Length > 33)
			{
				size = 64;
			}
			else
			{
				size = 32;
			}

			byte[] bytes = new byte[2 * size];
			byte[] x = BigIntegers.asUnsignedByteArray(size, bX);
			byte[] y = BigIntegers.asUnsignedByteArray(size, bY);

			for (int i = 0; i != size; i++)
			{
				bytes[i] = x[size - i - 1];
			}
			for (int i = 0; i != size; i++)
			{
				bytes[size + i] = y[size - i - 1];
			}

			digest.update(bytes, 0, bytes.Length);

			byte[] rv = new byte[digest.getDigestSize()];

			digest.doFinal(rv, 0);

			return rv;
		}
	}

}
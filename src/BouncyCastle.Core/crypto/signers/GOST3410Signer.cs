using BouncyCastle.Core;
using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.signers
{

	using GOST3410KeyParameters = org.bouncycastle.crypto.@params.GOST3410KeyParameters;
	using GOST3410Parameters = org.bouncycastle.crypto.@params.GOST3410Parameters;
	using GOST3410PrivateKeyParameters = org.bouncycastle.crypto.@params.GOST3410PrivateKeyParameters;
	using GOST3410PublicKeyParameters = org.bouncycastle.crypto.@params.GOST3410PublicKeyParameters;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using BigIntegers = org.bouncycastle.util.BigIntegers;

	/// <summary>
	/// GOST R 34.10-94 Signature Algorithm
	/// </summary>
	public class GOST3410Signer : DSAExt
	{
			internal GOST3410KeyParameters key;

			internal SecureRandom random;

			public virtual void init(bool forSigning, CipherParameters param)
			{
				if (forSigning)
				{
					if (param is ParametersWithRandom)
					{
						ParametersWithRandom rParam = (ParametersWithRandom)param;

						this.random = rParam.getRandom();
						this.key = (GOST3410PrivateKeyParameters)rParam.getParameters();
					}
					else
					{
						this.random = CryptoServicesRegistrar.getSecureRandom();
						this.key = (GOST3410PrivateKeyParameters)param;
					}
				}
				else
				{
					this.key = (GOST3410PublicKeyParameters)param;
				}
			}

			public virtual BigInteger getOrder()
			{
				return key.getParameters().getQ();
			}

			/// <summary>
			/// generate a signature for the given message using the key we were
			/// initialised with. For conventional GOST3410 the message should be a GOST3411
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

				BigInteger m = new BigInteger(1, mRev);
				GOST3410Parameters @params = key.getParameters();
				BigInteger k;

				do
				{
					k = BigIntegers.createRandomBigInteger(@params.getQ().bitLength(), random);
				} while (k.compareTo(@params.getQ()) >= 0);

				BigInteger r = @params.getA().modPow(k, @params.getP()).mod(@params.getQ());

				BigInteger s = k.multiply(m).add(((GOST3410PrivateKeyParameters)key).getX().multiply(r)).mod(@params.getQ());

				BigInteger[] res = new BigInteger[2];

				res[0] = r;
				res[1] = s;

				return res;
			}

			/// <summary>
			/// return true if the value r and s represent a GOST3410 signature for
			/// the passed in message for standard GOST3410 the message should be a
			/// GOST3411 hash of the real message to be verified.
			/// </summary>
			public virtual bool verifySignature(byte[] message, BigInteger r, BigInteger s)
			{
				byte[] mRev = new byte[message.Length]; // conversion is little-endian
				for (int i = 0; i != mRev.Length; i++)
				{
					mRev[i] = message[mRev.Length - 1 - i];
				}

				BigInteger m = new BigInteger(1, mRev);
				GOST3410Parameters @params = key.getParameters();
				BigInteger zero = BigInteger.valueOf(0);

				if (zero.compareTo(r) >= 0 || @params.getQ().compareTo(r) <= 0)
				{
					return false;
				}

				if (zero.compareTo(s) >= 0 || @params.getQ().compareTo(s) <= 0)
				{
					return false;
				}

				BigInteger v = m.modPow(@params.getQ().subtract(new BigInteger("2")),@params.getQ());

				BigInteger z1 = s.multiply(v).mod(@params.getQ());
				BigInteger z2 = (@params.getQ().subtract(r)).multiply(v).mod(@params.getQ());

				z1 = @params.getA().modPow(z1, @params.getP());
				z2 = ((GOST3410PublicKeyParameters)key).getY().modPow(z2, @params.getP());

				BigInteger u = z1.multiply(z2).mod(@params.getP()).mod(@params.getQ());

				return u.Equals(r);
			}
	}

}
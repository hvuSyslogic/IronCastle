using BouncyCastle.Core.Port;
using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.signers
{

	using DSAKeyParameters = org.bouncycastle.crypto.@params.DSAKeyParameters;
	using DSAParameters = org.bouncycastle.crypto.@params.DSAParameters;
	using DSAPrivateKeyParameters = org.bouncycastle.crypto.@params.DSAPrivateKeyParameters;
	using DSAPublicKeyParameters = org.bouncycastle.crypto.@params.DSAPublicKeyParameters;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using BigIntegers = org.bouncycastle.util.BigIntegers;

	/// <summary>
	/// The Digital Signature Algorithm - as described in "Handbook of Applied
	/// Cryptography", pages 452 - 453.
	/// </summary>
	public class DSASigner : DSAExt
	{
		private readonly DSAKCalculator kCalculator;

		private DSAKeyParameters key;
		private SecureRandom random;

		/// <summary>
		/// Default configuration, random K values.
		/// </summary>
		public DSASigner()
		{
			this.kCalculator = new RandomDSAKCalculator();
		}

		/// <summary>
		/// Configuration with an alternate, possibly deterministic calculator of K.
		/// </summary>
		/// <param name="kCalculator"> a K value calculator. </param>
		public DSASigner(DSAKCalculator kCalculator)
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

					this.key = (DSAPrivateKeyParameters)rParam.getParameters();
					providedRandom = rParam.getRandom();
				}
				else
				{
					this.key = (DSAPrivateKeyParameters)param;
				}
			}
			else
			{
				this.key = (DSAPublicKeyParameters)param;
			}

			this.random = initSecureRandom(forSigning && !kCalculator.isDeterministic(), providedRandom);
		}

		public virtual BigInteger getOrder()
		{
			return key.getParameters().getQ();
		}

		/// <summary>
		/// generate a signature for the given message using the key we were
		/// initialised with. For conventional DSA the message should be a SHA-1
		/// hash of the message of interest.
		/// </summary>
		/// <param name="message"> the message that will be verified later. </param>
		public virtual BigInteger[] generateSignature(byte[] message)
		{
			DSAParameters @params = key.getParameters();
			BigInteger q = @params.getQ();
			BigInteger m = calculateE(q, message);
			BigInteger x = ((DSAPrivateKeyParameters)key).getX();

			if (kCalculator.isDeterministic())
			{
				kCalculator.init(q, x, message);
			}
			else
			{
				kCalculator.init(q, random);
			}

			BigInteger k = kCalculator.nextK();

			// the randomizer is to conceal timing information related to k and x.
			BigInteger r = @params.getG().modPow(k.add(getRandomizer(q, random)), @params.getP()).mod(q);

			k = k.modInverse(q).multiply(m.add(x.multiply(r)));

			BigInteger s = k.mod(q);

			return new BigInteger[]{r, s};
		}

		/// <summary>
		/// return true if the value r and s represent a DSA signature for
		/// the passed in message for standard DSA the message should be a
		/// SHA-1 hash of the real message to be verified.
		/// </summary>
		public virtual bool verifySignature(byte[] message, BigInteger r, BigInteger s)
		{
			DSAParameters @params = key.getParameters();
			BigInteger q = @params.getQ();
			BigInteger m = calculateE(q, message);
			BigInteger zero = BigInteger.valueOf(0);

			if (zero.compareTo(r) >= 0 || q.compareTo(r) <= 0)
			{
				return false;
			}

			if (zero.compareTo(s) >= 0 || q.compareTo(s) <= 0)
			{
				return false;
			}

			BigInteger w = s.modInverse(q);

			BigInteger u1 = m.multiply(w).mod(q);
			BigInteger u2 = r.multiply(w).mod(q);

			BigInteger p = @params.getP();
			u1 = @params.getG().modPow(u1, p);
			u2 = ((DSAPublicKeyParameters)key).getY().modPow(u2, p);

			BigInteger v = u1.multiply(u2).mod(p).mod(q);

			return v.Equals(r);
		}

		private BigInteger calculateE(BigInteger n, byte[] message)
		{
			if (n.bitLength() >= message.Length * 8)
			{
				return new BigInteger(1, message);
			}
			else
			{
				byte[] trunc = new byte[n.bitLength() / 8];

				JavaSystem.arraycopy(message, 0, trunc, 0, trunc.Length);

				return new BigInteger(1, trunc);
			}
		}

		public virtual SecureRandom initSecureRandom(bool needed, SecureRandom provided)
		{
			return !needed ? null : (provided != null) ? provided : CryptoServicesRegistrar.getSecureRandom();
		}

		private BigInteger getRandomizer(BigInteger q, SecureRandom provided)
		{
			// Calculate a random multiple of q to add to k. Note that g^q = 1 (mod p), so adding multiple of q to k does not change r.
			int randomBits = 7;

			return BigIntegers.createRandomBigInteger(randomBits, provided != null ? provided : CryptoServicesRegistrar.getSecureRandom()).add(BigInteger.valueOf(128)).multiply(q);
		}
	}

}
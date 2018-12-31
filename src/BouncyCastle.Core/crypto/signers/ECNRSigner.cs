using BouncyCastle.Core;
using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.generators;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.math.ec;
using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.signers
{

									
	/// <summary>
	/// EC-NR as described in IEEE 1363-2000
	/// </summary>
	public class ECNRSigner : DSAExt
	{
		private bool forSigning;
		private ECKeyParameters key;
		private SecureRandom random;

		public virtual void init(bool forSigning, CipherParameters param)
		{
			this.forSigning = forSigning;

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

		// Section 7.2.5 ECSP-NR, pg 34
		/// <summary>
		/// generate a signature for the given message using the key we were
		/// initialised with.  Generally, the order of the curve should be at 
		/// least as long as the hash of the message of interest, and with 
		/// ECNR it *must* be at least as long.  
		/// </summary>
		/// <param name="digest">  the digest to be signed. </param>
		/// <exception cref="DataLengthException"> if the digest is longer than the key allows </exception>
		public virtual BigInteger[] generateSignature(byte[] digest)
		{
			if (!this.forSigning)
			{
				throw new IllegalStateException("not initialised for signing");
			}

			BigInteger n = getOrder();
			int nBitLength = n.bitLength();

			BigInteger e = new BigInteger(1, digest);
			int eBitLength = e.bitLength();

			ECPrivateKeyParameters privKey = (ECPrivateKeyParameters)key;

			if (eBitLength > nBitLength)
			{
				throw new DataLengthException("input too large for ECNR key.");
			}

			BigInteger r = null;
			BigInteger s = null;

			AsymmetricCipherKeyPair tempPair;
			do // generate r
			{
				// generate another, but very temporary, key pair using 
				// the same EC parameters
				ECKeyPairGenerator keyGen = new ECKeyPairGenerator();

				keyGen.init(new ECKeyGenerationParameters(privKey.getParameters(), this.random));

				tempPair = keyGen.generateKeyPair();

				//    BigInteger Vx = tempPair.getPublic().getW().getAffineX();
				ECPublicKeyParameters V = (ECPublicKeyParameters)tempPair.getPublic(); // get temp's public key
				BigInteger Vx = V.getQ().getAffineXCoord().toBigInteger(); // get the point's x coordinate

				r = Vx.add(e).mod(n);
			} while (r.Equals(ECConstants_Fields.ZERO));

			// generate s
			BigInteger x = privKey.getD(); // private key value
			BigInteger u = ((ECPrivateKeyParameters)tempPair.getPrivate()).getD(); // temp's private key value
			s = u.subtract(r.multiply(x)).mod(n);

			BigInteger[] res = new BigInteger[2];
			res[0] = r;
			res[1] = s;

			return res;
		}

		// Section 7.2.6 ECVP-NR, pg 35
		/// <summary>
		/// return true if the value r and s represent a signature for the 
		/// message passed in. Generally, the order of the curve should be at 
		/// least as long as the hash of the message of interest, and with 
		/// ECNR, it *must* be at least as long.  But just in case the signer
		/// applied mod(n) to the longer digest, this implementation will
		/// apply mod(n) during verification.
		/// </summary>
		/// <param name="digest">  the digest to be verified. </param>
		/// <param name="r">       the r value of the signature. </param>
		/// <param name="s">       the s value of the signature. </param>
		/// <exception cref="DataLengthException"> if the digest is longer than the key allows </exception>
		public virtual bool verifySignature(byte[] digest, BigInteger r, BigInteger s)
		{
			if (this.forSigning)
			{
				throw new IllegalStateException("not initialised for verifying");
			}

			ECPublicKeyParameters pubKey = (ECPublicKeyParameters)key;
			BigInteger n = pubKey.getParameters().getN();
			int nBitLength = n.bitLength();

			BigInteger e = new BigInteger(1, digest);
			int eBitLength = e.bitLength();

			if (eBitLength > nBitLength)
			{
				throw new DataLengthException("input too large for ECNR key.");
			}

			// r in the range [1,n-1]
			if (r.compareTo(ECConstants_Fields.ONE) < 0 || r.compareTo(n) >= 0)
			{
				return false;
			}

			// s in the range [0,n-1]           NB: ECNR spec says 0
			if (s.compareTo(ECConstants_Fields.ZERO) < 0 || s.compareTo(n) >= 0)
			{
				return false;
			}

			// compute P = sG + rW

			ECPoint G = pubKey.getParameters().getG();
			ECPoint W = pubKey.getQ();
			// calculate P using Bouncy math
			ECPoint P = ECAlgorithms.sumOfTwoMultiplies(G, s, W, r).normalize();

			// components must be bogus.
			if (P.isInfinity())
			{
				return false;
			}

			BigInteger x = P.getAffineXCoord().toBigInteger();
			BigInteger t = r.subtract(x).mod(n);

			return t.Equals(e);
		}
	}

}
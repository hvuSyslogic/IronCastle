using BouncyCastle.Core.Port;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.kems
{

	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using ECKeyParameters = org.bouncycastle.crypto.@params.ECKeyParameters;
	using ECPrivateKeyParameters = org.bouncycastle.crypto.@params.ECPrivateKeyParameters;
	using ECPublicKeyParameters = org.bouncycastle.crypto.@params.ECPublicKeyParameters;
	using KDFParameters = org.bouncycastle.crypto.@params.KDFParameters;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ECCurve = org.bouncycastle.math.ec.ECCurve;
	using ECMultiplier = org.bouncycastle.math.ec.ECMultiplier;
	using ECPoint = org.bouncycastle.math.ec.ECPoint;
	using FixedPointCombMultiplier = org.bouncycastle.math.ec.FixedPointCombMultiplier;
	using Arrays = org.bouncycastle.util.Arrays;
	using BigIntegers = org.bouncycastle.util.BigIntegers;

	/// <summary>
	/// The ECIES Key Encapsulation Mechanism (ECIES-KEM) from ISO 18033-2.
	/// </summary>
	public class ECIESKeyEncapsulation : KeyEncapsulation
	{
		private static readonly BigInteger ONE = BigInteger.valueOf(1);

		private DerivationFunction kdf;
		private SecureRandom rnd;
		private ECKeyParameters key;
		private bool CofactorMode;
		private bool OldCofactorMode;
		private bool SingleHashMode;

		/// <summary>
		/// Set up the ECIES-KEM.
		/// </summary>
		/// <param name="kdf"> the key derivation function to be used. </param>
		/// <param name="rnd"> the random source for the session key. </param>
		public ECIESKeyEncapsulation(DerivationFunction kdf, SecureRandom rnd)
		{
			this.kdf = kdf;
			this.rnd = rnd;
			this.CofactorMode = false;
			this.OldCofactorMode = false;
			this.SingleHashMode = false;
		}

		/// <summary>
		/// Set up the ECIES-KEM.
		/// </summary>
		/// <param name="kdf">             the key derivation function to be used. </param>
		/// <param name="rnd">             the random source for the session key. </param>
		/// <param name="cofactorMode">    if true use the new cofactor ECDH. </param>
		/// <param name="oldCofactorMode"> if true use the old cofactor ECDH. </param>
		/// <param name="singleHashMode">  if true use single hash mode. </param>
		public ECIESKeyEncapsulation(DerivationFunction kdf, SecureRandom rnd, bool cofactorMode, bool oldCofactorMode, bool singleHashMode)
		{
			this.kdf = kdf;
			this.rnd = rnd;

			// If both cofactorMode and oldCofactorMode are set to true
			// then the implementation will use the new cofactor ECDH 
			this.CofactorMode = cofactorMode;
			this.OldCofactorMode = oldCofactorMode;
			this.SingleHashMode = singleHashMode;
		}

		/// <summary>
		/// Initialise the ECIES-KEM.
		/// </summary>
		/// <param name="key"> the recipient's public (for encryption) or private (for decryption) key. </param>
		public virtual void init(CipherParameters key)
		{
			if (!(key is ECKeyParameters))
			{
				throw new IllegalArgumentException("EC key required");
			}
			else
			{
				this.key = (ECKeyParameters)key;
			}
		}

		/// <summary>
		/// Generate and encapsulate a random session key.
		/// </summary>
		/// <param name="out">    the output buffer for the encapsulated key. </param>
		/// <param name="outOff"> the offset for the output buffer. </param>
		/// <param name="keyLen"> the length of the session key. </param>
		/// <returns> the random session key. </returns>
		public virtual CipherParameters encrypt(byte[] @out, int outOff, int keyLen)
		{
			if (!(key is ECPublicKeyParameters))
			{
				throw new IllegalArgumentException("Public key required for encryption");
			}

			ECPublicKeyParameters ecPubKey = (ECPublicKeyParameters)key;
			ECDomainParameters ecParams = ecPubKey.getParameters();
			ECCurve curve = ecParams.getCurve();
			BigInteger n = ecParams.getN();
			BigInteger h = ecParams.getH();

			// Generate the ephemeral key pair    
			BigInteger r = BigIntegers.createRandomInRange(ONE, n, rnd);

			// Compute the static-ephemeral key agreement
			BigInteger rPrime = CofactorMode ? r.multiply(h).mod(n) : r;

			ECMultiplier basePointMultiplier = createBasePointMultiplier();

			ECPoint[] ghTilde = new ECPoint[]{basePointMultiplier.multiply(ecParams.getG(), r), ecPubKey.getQ().multiply(rPrime)};

			// NOTE: More efficient than normalizing each individually
			curve.normalizeAll(ghTilde);

			ECPoint gTilde = ghTilde[0], hTilde = ghTilde[1];

			// Encode the ephemeral public key
			byte[] C = gTilde.getEncoded(false);
			JavaSystem.arraycopy(C, 0, @out, outOff, C.Length);

			// Encode the shared secret value
			byte[] PEH = hTilde.getAffineXCoord().getEncoded();

			return deriveKey(keyLen, C, PEH);
		}

		/// <summary>
		/// Generate and encapsulate a random session key.
		/// </summary>
		/// <param name="out">    the output buffer for the encapsulated key. </param>
		/// <param name="keyLen"> the length of the session key. </param>
		/// <returns> the random session key. </returns>
		public virtual CipherParameters encrypt(byte[] @out, int keyLen)
		{
			return encrypt(@out, 0, keyLen);
		}

		/// <summary>
		/// Decrypt an encapsulated session key.
		/// </summary>
		/// <param name="in">     the input buffer for the encapsulated key. </param>
		/// <param name="inOff">  the offset for the input buffer. </param>
		/// <param name="inLen">  the length of the encapsulated key. </param>
		/// <param name="keyLen"> the length of the session key. </param>
		/// <returns> the session key. </returns>
		public virtual CipherParameters decrypt(byte[] @in, int inOff, int inLen, int keyLen)
		{
			if (!(key is ECPrivateKeyParameters))
			{
				throw new IllegalArgumentException("Private key required for encryption");
			}

			ECPrivateKeyParameters ecPrivKey = (ECPrivateKeyParameters)key;
			ECDomainParameters ecParams = ecPrivKey.getParameters();
			ECCurve curve = ecParams.getCurve();
			BigInteger n = ecParams.getN();
			BigInteger h = ecParams.getH();

			// Decode the ephemeral public key
			byte[] C = new byte[inLen];
			JavaSystem.arraycopy(@in, inOff, C, 0, inLen);

			// NOTE: Decoded points are already normalized (i.e in affine form)
			ECPoint gTilde = curve.decodePoint(C);

			// Compute the static-ephemeral key agreement
			ECPoint gHat = gTilde;
			if ((CofactorMode) || (OldCofactorMode))
			{
				gHat = gHat.multiply(h);
			}

			BigInteger xHat = ecPrivKey.getD();
			if (CofactorMode)
			{
				xHat = xHat.multiply(h.modInverse(n)).mod(n);
			}

			ECPoint hTilde = gHat.multiply(xHat).normalize();

			// Encode the shared secret value
			byte[] PEH = hTilde.getAffineXCoord().getEncoded();

			return deriveKey(keyLen, C, PEH);
		}

		/// <summary>
		/// Decrypt an encapsulated session key.
		/// </summary>
		/// <param name="in">     the input buffer for the encapsulated key. </param>
		/// <param name="keyLen"> the length of the session key. </param>
		/// <returns> the session key. </returns>
		public virtual CipherParameters decrypt(byte[] @in, int keyLen)
		{
			return decrypt(@in, 0, @in.Length, keyLen);
		}

		public virtual ECMultiplier createBasePointMultiplier()
		{
			return new FixedPointCombMultiplier();
		}

		public virtual KeyParameter deriveKey(int keyLen, byte[] C, byte[] PEH)
		{
			byte[] kdfInput = PEH;
			if (!SingleHashMode)
			{
				kdfInput = Arrays.concatenate(C, PEH);
				Arrays.fill(PEH, 0);
			}

			try
			{
				// Initialise the KDF
				kdf.init(new KDFParameters(kdfInput, null));

				// Generate the secret key
				byte[] K = new byte[keyLen];
				kdf.generateBytes(K, 0, K.Length);

				// Return the ciphertext
				return new KeyParameter(K);
			}
			finally
			{
				Arrays.fill(kdfInput, 0);
			}
		}
	}

}
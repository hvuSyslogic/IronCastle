using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.kems
{

				
	/// <summary>
	/// The RSA Key Encapsulation Mechanism (RSA-KEM) from ISO 18033-2.
	/// </summary>
	public class RSAKeyEncapsulation : KeyEncapsulation
	{
		private static readonly BigInteger ZERO = BigInteger.valueOf(0);
		private static readonly BigInteger ONE = BigInteger.valueOf(1);

		private DerivationFunction kdf;
		private SecureRandom rnd;
		private RSAKeyParameters key;

		/// <summary>
		/// Set up the RSA-KEM.
		/// </summary>
		/// <param name="kdf"> the key derivation function to be used. </param>
		/// <param name="rnd"> the random source for the session key. </param>
		public RSAKeyEncapsulation(DerivationFunction kdf, SecureRandom rnd)
		{
			this.kdf = kdf;
			this.rnd = rnd;
		}

		/// <summary>
		/// Initialise the RSA-KEM.
		/// </summary>
		/// <param name="key"> the recipient's public (for encryption) or private (for decryption) key. </param>
		public virtual void init(CipherParameters key)
		{
			if (!(key is RSAKeyParameters))
			{
				throw new IllegalArgumentException("RSA key required");
			}

			this.key = (RSAKeyParameters)key;
		}

		/// <summary>
		/// Generate and encapsulate a random session key.
		/// </summary>
		/// <param name="out">    the output buffer for the encapsulated key. </param>
		/// <param name="outOff"> the offset for the output buffer. </param>
		/// <param name="keyLen"> the length of the random session key. </param>
		/// <returns> the random session key. </returns>
		public virtual CipherParameters encrypt(byte[] @out, int outOff, int keyLen)
		{
			if (key.isPrivate())
			{
				throw new IllegalArgumentException("Public key required for encryption");
			}

			BigInteger n = key.getModulus();
			BigInteger e = key.getExponent();

			// Generate the ephemeral random and encode it    
			BigInteger r = BigIntegers.createRandomInRange(ZERO, n.subtract(ONE), rnd);

			// Encrypt the random and encode it     
			BigInteger c = r.modPow(e, n);
			byte[] C = BigIntegers.asUnsignedByteArray((n.bitLength() + 7) / 8, c);
			JavaSystem.arraycopy(C, 0, @out, outOff, C.Length);

			return generateKey(n, r, keyLen);
		}

		/// <summary>
		/// Generate and encapsulate a random session key.
		/// </summary>
		/// <param name="out">    the output buffer for the encapsulated key. </param>
		/// <param name="keyLen"> the length of the random session key. </param>
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
			if (!key.isPrivate())
			{
				throw new IllegalArgumentException("Private key required for decryption");
			}

			BigInteger n = key.getModulus();
			BigInteger d = key.getExponent();

			// Decode the input
			byte[] C = new byte[inLen];
			JavaSystem.arraycopy(@in, inOff, C, 0, C.Length);
			BigInteger c = new BigInteger(1, C);

			// Decrypt the ephemeral random and encode it
			BigInteger r = c.modPow(d, n);

			return generateKey(n, r, keyLen);
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

		public virtual KeyParameter generateKey(BigInteger n, BigInteger r, int keyLen)
		{
			byte[] R = BigIntegers.asUnsignedByteArray((n.bitLength() + 7) / 8, r);

			// Initialise the KDF
			kdf.init(new KDFParameters(R, null));

			// Generate the secret key
			byte[] K = new byte[keyLen];
			kdf.generateBytes(K, 0, K.Length);

			return new KeyParameter(K);
		}
	}

}
namespace org.bouncycastle.crypto.digests
{
	using Memoable = org.bouncycastle.util.Memoable;
	using Pack = org.bouncycastle.util.Pack;


	/// <summary>
	/// FIPS 180-2 implementation of SHA-512.
	/// 
	/// <pre>
	///         block  word  digest
	/// SHA-1   512    32    160
	/// SHA-256 512    32    256
	/// SHA-384 1024   64    384
	/// SHA-512 1024   64    512
	/// </pre>
	/// </summary>
	public class SHA512Digest : LongDigest
	{
		private const int DIGEST_LENGTH = 64;

		/// <summary>
		/// Standard constructor
		/// </summary>
		public SHA512Digest()
		{
		}

		/// <summary>
		/// Copy constructor.  This will copy the state of the provided
		/// message digest.
		/// </summary>
		public SHA512Digest(SHA512Digest t) : base(t)
		{
		}

		/// <summary>
		/// State constructor - create a digest initialised with the state of a previous one.
		/// </summary>
		/// <param name="encodedState"> the encoded state from the originating digest. </param>
		public SHA512Digest(byte[] encodedState)
		{
			restoreState(encodedState);
		}

		public override string getAlgorithmName()
		{
			return "SHA-512";
		}

		public override int getDigestSize()
		{
			return DIGEST_LENGTH;
		}

		public override int doFinal(byte[] @out, int outOff)
		{
			finish();

			Pack.longToBigEndian(H1, @out, outOff);
			Pack.longToBigEndian(H2, @out, outOff + 8);
			Pack.longToBigEndian(H3, @out, outOff + 16);
			Pack.longToBigEndian(H4, @out, outOff + 24);
			Pack.longToBigEndian(H5, @out, outOff + 32);
			Pack.longToBigEndian(H6, @out, outOff + 40);
			Pack.longToBigEndian(H7, @out, outOff + 48);
			Pack.longToBigEndian(H8, @out, outOff + 56);

			reset();

			return DIGEST_LENGTH;
		}

		/// <summary>
		/// reset the chaining variables
		/// </summary>
		public override void reset()
		{
			base.reset();

			/* SHA-512 initial hash value
			 * The first 64 bits of the fractional parts of the square roots
			 * of the first eight prime numbers
			 */
			H1 = 0x6a09e667f3bcc908L;
			H2 = unchecked((long)0xbb67ae8584caa73bL);
			H3 = 0x3c6ef372fe94f82bL;
			H4 = unchecked((long)0xa54ff53a5f1d36f1L);
			H5 = 0x510e527fade682d1L;
			H6 = unchecked((long)0x9b05688c2b3e6c1fL);
			H7 = 0x1f83d9abfb41bd6bL;
			H8 = 0x5be0cd19137e2179L;
		}

		public override Memoable copy()
		{
			return new SHA512Digest(this);
		}

		public override void reset(Memoable other)
		{
			SHA512Digest d = (SHA512Digest)other;

			copyIn(d);
		}

		public override byte[] getEncodedState()
		{
			byte[] encoded = new byte[getEncodedStateSize()];
			base.populateState(encoded);
			return encoded;
		}
	}


}
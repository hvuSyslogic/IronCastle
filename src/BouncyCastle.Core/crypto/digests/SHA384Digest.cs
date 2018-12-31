namespace org.bouncycastle.crypto.digests
{
	using Memoable = org.bouncycastle.util.Memoable;
	using Pack = org.bouncycastle.util.Pack;


	/// <summary>
	/// FIPS 180-2 implementation of SHA-384.
	/// 
	/// <pre>
	///         block  word  digest
	/// SHA-1   512    32    160
	/// SHA-256 512    32    256
	/// SHA-384 1024   64    384
	/// SHA-512 1024   64    512
	/// </pre>
	/// </summary>
	public class SHA384Digest : LongDigest
	{
		private const int DIGEST_LENGTH = 48;

		/// <summary>
		/// Standard constructor
		/// </summary>
		public SHA384Digest()
		{
		}

		/// <summary>
		/// Copy constructor.  This will copy the state of the provided
		/// message digest.
		/// </summary>
		public SHA384Digest(SHA384Digest t) : base(t)
		{
		}

		/// <summary>
		/// State constructor - create a digest initialised with the state of a previous one.
		/// </summary>
		/// <param name="encodedState"> the encoded state from the originating digest. </param>
		public SHA384Digest(byte[] encodedState)
		{
			restoreState(encodedState);
		}

		public override string getAlgorithmName()
		{
			return "SHA-384";
		}

		public override int getDigestSize()
		{
			return DIGEST_LENGTH;
		}

		public override int doFinal(byte[] @out, int outOff)
		{
			finish();

			Pack.ulongToBigEndian(H1, @out, outOff);
			Pack.ulongToBigEndian(H2, @out, outOff + 8);
			Pack.ulongToBigEndian(H3, @out, outOff + 16);
			Pack.ulongToBigEndian(H4, @out, outOff + 24);
			Pack.ulongToBigEndian(H5, @out, outOff + 32);
			Pack.ulongToBigEndian(H6, @out, outOff + 40);

			reset();

			return DIGEST_LENGTH;
		}

		/// <summary>
		/// reset the chaining variables
		/// </summary>
		public override void reset()
		{
			base.reset();

			/* SHA-384 initial hash value
			 * The first 64 bits of the fractional parts of the square roots
			 * of the 9th through 16th prime numbers
			 */
			H1 = unchecked(0xcbbb9d5dc1059ed8Ul);
			H2 = 0x629a292a367cd507l;
			H3 = unchecked(0x9159015a3070dd17Ul);
			H4 = 0x152fecd8f70e5939Ul;
			H5 = 0x67332667ffc00b31Ul;
			H6 = unchecked(0x8eb44a8768581511Ul);
			H7 = unchecked(0xdb0c2e0d64f98fa7Ul);
			H8 = 0x47b5481dbefa4fa4Ul;
		}

		public override Memoable copy()
		{
			return new SHA384Digest(this);
		}

		public override void reset(Memoable other)
		{
			SHA384Digest d = (SHA384Digest)other;

			base.copyIn(d);
		}

		public override byte[] getEncodedState()
		{
			byte[] encoded = new byte[getEncodedStateSize()];
			base.populateState(encoded);
			return encoded;
		}
	}

}
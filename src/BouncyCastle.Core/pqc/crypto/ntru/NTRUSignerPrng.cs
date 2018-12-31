using org.bouncycastle.crypto;

namespace org.bouncycastle.pqc.crypto.ntru
{

	
	/// <summary>
	/// An implementation of the deterministic pseudo-random generator in EESS section 3.7.3.1
	/// </summary>
	public class NTRUSignerPrng
	{
		private int counter;
		private byte[] seed;
		private Digest hashAlg;

		/// <summary>
		/// Constructs a new PRNG and seeds it with a byte array.
		/// </summary>
		/// <param name="seed">    a seed </param>
		/// <param name="hashAlg"> the hash algorithm to use </param>
		public NTRUSignerPrng(byte[] seed, Digest hashAlg)
		{
			counter = 0;
			this.seed = seed;
			this.hashAlg = hashAlg;
		}

		/// <summary>
		/// Returns <code>n</code> random bytes
		/// </summary>
		/// <param name="n"> number of bytes to return </param>
		/// <returns> the next <code>n</code> random bytes </returns>
		public virtual byte[] nextBytes(int n)
		{
			ByteBuffer buf = ByteBuffer.allocate(n);

			while (buf.hasRemaining())
			{
				ByteBuffer cbuf = ByteBuffer.allocate(seed.Length + 4);
				cbuf.put(seed);
				cbuf.putInt(counter);
				byte[] array = cbuf.array();
				byte[] hash = new byte[hashAlg.getDigestSize()];

				hashAlg.update(array, 0, array.Length);

				hashAlg.doFinal(hash, 0);

				if (buf.remaining() < hash.Length)
				{
					buf.put(hash, 0, buf.remaining());
				}
				else
				{
					buf.put(hash);
				}
				counter++;
			}

			return buf.array();
		}
	}
}
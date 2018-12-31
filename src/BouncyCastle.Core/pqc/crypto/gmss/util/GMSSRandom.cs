using org.bouncycastle.crypto;

namespace org.bouncycastle.pqc.crypto.gmss.util
{
	
	/// <summary>
	/// This class provides a PRNG for GMSS
	/// </summary>
	public class GMSSRandom
	{
		/// <summary>
		/// Hash function for the construction of the authentication trees
		/// </summary>
		private Digest messDigestTree;

		/// <summary>
		/// Constructor
		/// </summary>
		/// <param name="messDigestTree2"> </param>
		public GMSSRandom(Digest messDigestTree2)
		{

			this.messDigestTree = messDigestTree2;
		}

		/// <summary>
		/// computes the next seed value, returns a random byte array and sets
		/// outseed to the next value
		/// </summary>
		/// <param name="outseed"> byte array in which ((1 + SEEDin +RAND) mod 2^n) will be
		///                stored </param>
		/// <returns> byte array of H(SEEDin) </returns>
		public virtual byte[] nextSeed(byte[] outseed)
		{
			// RAND <-- H(SEEDin)
			byte[] rand = new byte[outseed.Length];
			messDigestTree.update(outseed, 0, outseed.Length);
			rand = new byte[messDigestTree.getDigestSize()];
			messDigestTree.doFinal(rand, 0);

			// SEEDout <-- (1 + SEEDin +RAND) mod 2^n
			addByteArrays(outseed, rand);
			addOne(outseed);

			// JavaSystem.arraycopy(outseed, 0, outseed, 0, outseed.length);

			return rand;
		}

		private void addByteArrays(byte[] a, byte[] b)
		{

			byte overflow = 0;
			int temp;

			for (int i = 0; i < a.Length; i++)
			{
				temp = (0xFF & a[i]) + (0xFF & b[i]) + overflow;
				a[i] = (byte)temp;
				overflow = (byte)(temp >> 8);
			}
		}

		private void addOne(byte[] a)
		{

			byte overflow = 1;
			int temp;

			for (int i = 0; i < a.Length; i++)
			{
				temp = (0xFF & a[i]) + overflow;
				a[i] = (byte)temp;
				overflow = (byte)(temp >> 8);
			}
		}
	}

}
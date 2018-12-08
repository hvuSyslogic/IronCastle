using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.prng
{
	/// <summary>
	/// Utility methods for making use of EntropySources.
	/// </summary>
	public class EntropyUtil
	{
		/// <summary>
		/// Generate numBytes worth of entropy from the passed in entropy source.
		/// </summary>
		/// <param name="entropySource"> the entropy source to request the data from. </param>
		/// <param name="numBytes"> the number of bytes of entropy requested. </param>
		/// <returns> a byte array populated with the random data. </returns>
		public static byte[] generateSeed(EntropySource entropySource, int numBytes)
		{
			byte[] bytes = new byte[numBytes];

			if (numBytes * 8 <= entropySource.entropySize())
			{
				byte[] ent = entropySource.getEntropy();

				JavaSystem.arraycopy(ent, 0, bytes, 0, bytes.Length);
			}
			else
			{
				int entSize = entropySource.entropySize() / 8;

				for (int i = 0; i < bytes.Length; i += entSize)
				{
					byte[] ent = entropySource.getEntropy();

					if (ent.Length <= bytes.Length - i)
					{
						JavaSystem.arraycopy(ent, 0, bytes, i, ent.Length);
					}
					else
					{
						JavaSystem.arraycopy(ent, 0, bytes, i, bytes.Length - i);
					}
				}
			}

			return bytes;
		}
	}

}
namespace org.bouncycastle.jcajce.provider.asymmetric.util
{
	public class PrimeCertaintyCalculator
	{
		private PrimeCertaintyCalculator()
		{

		}

		/// <summary>
		/// Return the current wisdom on prime certainty requirements.
		/// </summary>
		/// <param name="keySizeInBits"> size of the key being generated. </param>
		/// <returns> a certainty value. </returns>
		public static int getDefaultCertainty(int keySizeInBits)
		{
			// Based on FIPS 186-4 Table C.1
			return keySizeInBits <= 1024 ? 80 : (96 + 16 * ((keySizeInBits - 1) / 1024));
		}
	}

}
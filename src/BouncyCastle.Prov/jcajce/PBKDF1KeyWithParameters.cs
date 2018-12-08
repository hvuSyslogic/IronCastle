namespace org.bouncycastle.jcajce
{

	using CharToByteConverter = org.bouncycastle.crypto.CharToByteConverter;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// A password based key for use with PBKDF1 as defined in PKCS#5 with full PBE parameters.
	/// </summary>
	public class PBKDF1KeyWithParameters : PBKDF1Key, PBEKey
	{
		private readonly byte[] salt;
		private readonly int iterationCount;

		/// <summary>
		/// Basic constructor for a password based key with generation parameters for PBKDF1.
		/// </summary>
		/// <param name="password"> password to use. </param>
		/// <param name="converter"> the converter to use to turn the char array into octets. </param>
		/// <param name="salt"> salt for generation algorithm </param>
		/// <param name="iterationCount"> iteration count for generation algorithm. </param>
		public PBKDF1KeyWithParameters(char[] password, CharToByteConverter converter, byte[] salt, int iterationCount) : base(password, converter)
		{

			this.salt = Arrays.clone(salt);
			this.iterationCount = iterationCount;
		}

		/// <summary>
		/// Return the salt to use in the key derivation function.
		/// </summary>
		/// <returns> the salt to use in the KDF. </returns>
		public virtual byte[] getSalt()
		{
			return salt;
		}

		/// <summary>
		/// Return the iteration count to use in the key derivation function.
		/// </summary>
		/// <returns> the iteration count to use in the KDF. </returns>
		public virtual int getIterationCount()
		{
			return iterationCount;
		}
	}

}
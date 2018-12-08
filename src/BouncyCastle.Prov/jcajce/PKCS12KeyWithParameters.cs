namespace org.bouncycastle.jcajce
{

	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// A password based key for use with PKCS#12 with full PBE parameters.
	/// </summary>
	public class PKCS12KeyWithParameters : PKCS12Key, PBEKey
	{
		private readonly byte[] salt;
		private readonly int iterationCount;

		/// <summary>
		/// Basic constructor for a password based key with generation parameters.
		/// </summary>
		/// <param name="password"> password to use. </param>
		/// <param name="salt"> salt for generation algorithm </param>
		/// <param name="iterationCount"> iteration count for generation algorithm. </param>
		public PKCS12KeyWithParameters(char[] password, byte[] salt, int iterationCount) : base(password)
		{

			this.salt = Arrays.clone(salt);
			this.iterationCount = iterationCount;
		}


		/// <summary>
		/// Basic constructor for a password based key with generation parameters, specifying the wrong conversion for
		/// zero length passwords.
		/// </summary>
		/// <param name="password"> password to use. </param>
		/// <param name="salt"> salt for generation algorithm </param>
		/// <param name="iterationCount"> iteration count for generation algorithm. </param>
		/// <param name="useWrongZeroLengthConversion"> use the incorrect encoding approach (add pad bytes) </param>
		public PKCS12KeyWithParameters(char[] password, bool useWrongZeroLengthConversion, byte[] salt, int iterationCount) : base(password, useWrongZeroLengthConversion)
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
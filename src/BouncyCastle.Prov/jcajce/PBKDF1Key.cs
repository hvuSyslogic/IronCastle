namespace org.bouncycastle.jcajce
{
	using CharToByteConverter = org.bouncycastle.crypto.CharToByteConverter;

	/// <summary>
	/// A password based key for use with PBKDF1 as defined in PKCS#5.
	/// </summary>
	public class PBKDF1Key : PBKDFKey
	{
		private readonly char[] password;
		private readonly CharToByteConverter converter;

		/// <summary>
		/// Basic constructor for a password based key with generation parameters for PBKDF1.
		/// </summary>
		/// <param name="password"> password to use. </param>
		/// <param name="converter"> the converter to use to turn the char array into octets. </param>
		public PBKDF1Key(char[] password, CharToByteConverter converter)
		{
			this.password = new char[password.Length];
			this.converter = converter;

			JavaSystem.arraycopy(password, 0, this.password, 0, password.Length);
		}

		/// <summary>
		/// Return a reference to the char[] array holding the password.
		/// </summary>
		/// <returns> a reference to the password array. </returns>
		public virtual char[] getPassword()
		{
			return password;
		}

		/// <summary>
		/// Return the password based key derivation function this key is for,
		/// </summary>
		/// <returns> the string "PBKDF1" </returns>
		public virtual string getAlgorithm()
		{
			return "PBKDF1";
		}

		/// <summary>
		/// Return the format encoding.
		/// </summary>
		/// <returns> the type name representing a char[] to byte[] conversion. </returns>
		public virtual string getFormat()
		{
			return converter.getType();
		}

		/// <summary>
		/// Return the password converted to bytes.
		/// </summary>
		/// <returns> the password converted to a byte array. </returns>
		public virtual byte[] getEncoded()
		{
			return converter.convert(password);
		}
	}

}
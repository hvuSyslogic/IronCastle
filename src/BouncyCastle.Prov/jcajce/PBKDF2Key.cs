namespace org.bouncycastle.jcajce
{
	using CharToByteConverter = org.bouncycastle.crypto.CharToByteConverter;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// A password based key for use with PBKDF2 as defined in PKCS#5.
	/// </summary>
	public class PBKDF2Key : PBKDFKey
	{
		private readonly char[] password;
		private readonly CharToByteConverter converter;

		/// <summary>
		/// Basic constructor for a password based key using PBKDF - secret key generation parameters will be passed separately..
		/// </summary>
		/// <param name="password"> password to use. </param>
		public PBKDF2Key(char[] password, CharToByteConverter converter)
		{
			this.password = Arrays.clone(password);
			this.converter = converter;
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
		/// <returns> the string "PBKDF2" </returns>
		public virtual string getAlgorithm()
		{
			return "PBKDF2";
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
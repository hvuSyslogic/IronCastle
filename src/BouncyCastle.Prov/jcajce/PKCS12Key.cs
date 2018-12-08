namespace org.bouncycastle.jcajce
{
	using PBEParametersGenerator = org.bouncycastle.crypto.PBEParametersGenerator;

	/// <summary>
	/// A password based key for use with PKCS#12.
	/// </summary>
	public class PKCS12Key : PBKDFKey
	{
		private readonly char[] password;
		private readonly bool useWrongZeroLengthConversion;
		/// <summary>
		/// Basic constructor for a password based key - secret key generation parameters will be passed separately..
		/// </summary>
		/// <param name="password"> password to use. </param>
		public PKCS12Key(char[] password) : this(password, false)
		{
		}

		/// <summary>
		/// Unfortunately there seems to be some confusion about how to handle zero length
		/// passwords.
		/// </summary>
		/// <param name="password"> password to use. </param>
		/// <param name="useWrongZeroLengthConversion"> use the incorrect encoding approach (add pad bytes) </param>
		public PKCS12Key(char[] password, bool useWrongZeroLengthConversion)
		{
			if (password == null)
			{
				password = new char[0];
			}

			this.password = new char[password.Length];
			this.useWrongZeroLengthConversion = useWrongZeroLengthConversion;

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
		/// <returns> the string "PKCS12" </returns>
		public virtual string getAlgorithm()
		{
			return "PKCS12";
		}

		/// <summary>
		/// Return the format encoding.
		/// </summary>
		/// <returns> the string "PKCS12", representing the char[] to byte[] conversion. </returns>
		public virtual string getFormat()
		{
			return "PKCS12";
		}

		/// <summary>
		/// Return the password converted to bytes.
		/// </summary>
		/// <returns> the password converted to a byte array. </returns>
		public virtual byte[] getEncoded()
		{
			if (useWrongZeroLengthConversion && password.Length == 0)
			{
				return new byte[2];
			}

			return PBEParametersGenerator.PKCS12PasswordToBytes(password);
		}
	}

}
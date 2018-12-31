using org.bouncycastle.util;

namespace org.bouncycastle.crypto
{
	
	/// <summary>
	/// super class for all Password Based Encryption (PBE) parameter generator classes.
	/// </summary>
	public abstract class PBEParametersGenerator
	{
		protected internal byte[] password;
		protected internal byte[] salt;
		protected internal int iterationCount;

		/// <summary>
		/// base constructor.
		/// </summary>
		public PBEParametersGenerator()
		{
		}

		/// <summary>
		/// initialise the PBE generator.
		/// </summary>
		/// <param name="password"> the password converted into bytes (see below). </param>
		/// <param name="salt"> the salt to be mixed with the password. </param>
		/// <param name="iterationCount"> the number of iterations the "mixing" function
		/// is to be applied for. </param>
		public virtual void init(byte[] password, byte[] salt, int iterationCount)
		{
			this.password = password;
			this.salt = salt;
			this.iterationCount = iterationCount;
		}

		/// <summary>
		/// return the password byte array.
		/// </summary>
		/// <returns> the password byte array. </returns>
		public virtual byte[] getPassword()
		{
			return password;
		}

		/// <summary>
		/// return the salt byte array.
		/// </summary>
		/// <returns> the salt byte array. </returns>
		public virtual byte[] getSalt()
		{
			return salt;
		}

		/// <summary>
		/// return the iteration count.
		/// </summary>
		/// <returns> the iteration count. </returns>
		public virtual int getIterationCount()
		{
			return iterationCount;
		}

		/// <summary>
		/// generate derived parameters for a key of length keySize.
		/// </summary>
		/// <param name="keySize"> the length, in bits, of the key required. </param>
		/// <returns> a parameters object representing a key. </returns>
		public abstract CipherParameters generateDerivedParameters(int keySize);

		/// <summary>
		/// generate derived parameters for a key of length keySize, and
		/// an initialisation vector (IV) of length ivSize.
		/// </summary>
		/// <param name="keySize"> the length, in bits, of the key required. </param>
		/// <param name="ivSize"> the length, in bits, of the iv required. </param>
		/// <returns> a parameters object representing a key and an IV. </returns>
		public abstract CipherParameters generateDerivedParameters(int keySize, int ivSize);

		/// <summary>
		/// generate derived parameters for a key of length keySize, specifically
		/// for use with a MAC.
		/// </summary>
		/// <param name="keySize"> the length, in bits, of the key required. </param>
		/// <returns> a parameters object representing a key. </returns>
		public abstract CipherParameters generateDerivedMacParameters(int keySize);

		/// <summary>
		/// converts a password to a byte array according to the scheme in
		/// PKCS5 (ascii, no padding)
		/// </summary>
		/// <param name="password"> a character array representing the password. </param>
		/// <returns> a byte array representing the password. </returns>
		public static byte[] PKCS5PasswordToBytes(char[] password)
		{
			if (password != null)
			{
				byte[] bytes = new byte[password.Length];

				for (int i = 0; i != bytes.Length; i++)
				{
					bytes[i] = (byte)password[i];
				}

				return bytes;
			}
			else
			{
				return new byte[0];
			}
		}

		/// <summary>
		/// converts a password to a byte array according to the scheme in
		/// PKCS5 (UTF-8, no padding)
		/// </summary>
		/// <param name="password"> a character array representing the password. </param>
		/// <returns> a byte array representing the password. </returns>
		public static byte[] PKCS5PasswordToUTF8Bytes(char[] password)
		{
			if (password != null)
			{
				return Strings.toUTF8ByteArray(password);
			}
			else
			{
				return new byte[0];
			}
		}

		/// <summary>
		/// converts a password to a byte array according to the scheme in
		/// PKCS12 (unicode, big endian, 2 zero pad bytes at the end).
		/// </summary>
		/// <param name="password"> a character array representing the password. </param>
		/// <returns> a byte array representing the password. </returns>
		public static byte[] PKCS12PasswordToBytes(char[] password)
		{
			if (password != null && password.Length > 0)
			{
										   // +1 for extra 2 pad bytes.
				byte[] bytes = new byte[(password.Length + 1) * 2];

				for (int i = 0; i != password.Length; i++)
				{
					bytes[i * 2] = (byte)((int)((uint)password[i] >> 8));
					bytes[i * 2 + 1] = (byte)password[i];
				}

				return bytes;
			}
			else
			{
				return new byte[0];
			}
		}
	}

}
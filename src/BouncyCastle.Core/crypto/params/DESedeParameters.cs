using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.@params
{
	public class DESedeParameters : DESParameters
	{
		/*
		 * DES-EDE Key length in bytes.
		 */
		public const int DES_EDE_KEY_LENGTH = 24;

		public DESedeParameters(byte[] key) : base(key)
		{

			if (isWeakKey(key, 0, key.Length))
			{
				throw new IllegalArgumentException("attempt to create weak DESede key");
			}
		}

		/// <summary>
		/// return true if the passed in key is a DES-EDE weak key.
		/// </summary>
		/// <param name="key"> bytes making up the key </param>
		/// <param name="offset"> offset into the byte array the key starts at </param>
		/// <param name="length"> number of bytes making up the key </param>
		public static bool isWeakKey(byte[] key, int offset, int length)
		{
			for (int i = offset; i < length; i += DES_KEY_LENGTH)
			{
				if (DESParameters.isWeakKey(key, i))
				{
					return true;
				}
			}

			return false;
		}

		/// <summary>
		/// return true if the passed in key is a DES-EDE weak key.
		/// </summary>
		/// <param name="key"> bytes making up the key </param>
		/// <param name="offset"> offset into the byte array the key starts at </param>
		public static bool isWeakKey(byte[] key, int offset)
		{
			return isWeakKey(key, offset, key.Length - offset);
		}

		/// <summary>
		/// return true if the passed in key is a real 2/3 part DES-EDE key.
		/// </summary>
		/// <param name="key"> bytes making up the key </param>
		/// <param name="offset"> offset into the byte array the key starts at </param>
		public static bool isRealEDEKey(byte[] key, int offset)
		{
			return key.Length == 16 ? isReal2Key(key, offset) : isReal3Key(key, offset);
		}

		/// <summary>
		/// return true if the passed in key is a real 2 part DES-EDE key.
		/// </summary>
		/// <param name="key"> bytes making up the key </param>
		/// <param name="offset"> offset into the byte array the key starts at </param>
		public static bool isReal2Key(byte[] key, int offset)
		{
			bool isValid = false;
			for (int i = offset; i != offset + 8; i++)
			{
				if (key[i] != key[i + 8])
				{
					isValid = true;
				}
			}

			return isValid;
		}

		/// <summary>
		/// return true if the passed in key is a real 3 part DES-EDE key.
		/// </summary>
		/// <param name="key"> bytes making up the key </param>
		/// <param name="offset"> offset into the byte array the key starts at </param>
		public static bool isReal3Key(byte[] key, int offset)
		{
			bool diff12 = false, diff13 = false, diff23 = false;
			for (int i = offset; i != offset + 8; i++)
			{
				diff12 |= (key[i] != key[i + 8]);
				diff13 |= (key[i] != key[i + 16]);
				diff23 |= (key[i + 8] != key[i + 16]);
			}
			return diff12 && diff13 && diff23;
		}
	}

}
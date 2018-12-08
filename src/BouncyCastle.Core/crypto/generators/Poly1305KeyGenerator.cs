using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.generators
{
	using Poly1305 = org.bouncycastle.crypto.macs.Poly1305;

	/// <summary>
	/// Generates keys for the Poly1305 MAC.
	/// <para>
	/// Poly1305 keys are 256 bit keys consisting of a 128 bit secret key used for the underlying block
	/// cipher followed by a 128 bit {@code r} value used for the polynomial portion of the Mac. <br>
	/// The {@code r} value has a specific format with some bits required to be cleared, resulting in an
	/// effective 106 bit key. <br>
	/// A separately generated 256 bit key can be modified to fit the Poly1305 key format by using the
	/// <seealso cref="#clamp(byte[])"/> method to clear the required bits.
	/// 
	/// </para>
	/// </summary>
	/// <seealso cref= Poly1305 </seealso>
	public class Poly1305KeyGenerator : CipherKeyGenerator
	{
		private static readonly byte R_MASK_LOW_2 = unchecked((byte)0xFC);
		private static readonly byte R_MASK_HIGH_4 = (byte)0x0F;

		/// <summary>
		/// Initialises the key generator.<br>
		/// Poly1305 keys are always 256 bits, so the key length in the provided parameters is ignored.
		/// </summary>
		public override void init(KeyGenerationParameters param)
		{
			// Poly1305 keys are always 256 bits
			base.init(new KeyGenerationParameters(param.getRandom(), 256));
		}

		/// <summary>
		/// Generates a 256 bit key in the format required for Poly1305 - e.g.
		/// <code>k[0] ... k[15], r[0] ... r[15]</code> with the required bits in <code>r</code> cleared
		/// as per <seealso cref="#clamp(byte[])"/>.
		/// </summary>
		public override byte[] generateKey()
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final byte[] key = super.generateKey();
			byte[] key = base.generateKey();
			clamp(key);
			return key;
		}

		/// <summary>
		/// Modifies an existing 32 byte key value to comply with the requirements of the Poly1305 key by
		/// clearing required bits in the <code>r</code> (second 16 bytes) portion of the key.<br>
		/// Specifically:
		/// <ul>
		/// <li>r[3], r[7], r[11], r[15] have top four bits clear (i.e., are {0, 1, . . . , 15})</li>
		/// <li>r[4], r[8], r[12] have bottom two bits clear (i.e., are in {0, 4, 8, . . . , 252})</li>
		/// </ul>
		/// </summary>
		/// <param name="key"> a 32 byte key value <code>k[0] ... k[15], r[0] ... r[15]</code> </param>
		public static void clamp(byte[] key)
		{
			/*
			 * Key is k[0] ... k[15], r[0] ... r[15] as per poly1305_aes_clamp in ref impl.
			 */
			if (key.Length != 32)
			{
				throw new IllegalArgumentException("Poly1305 key must be 256 bits.");
			}

			/*
			 * r[3], r[7], r[11], r[15] have top four bits clear (i.e., are {0, 1, . . . , 15})
			 */
			key[3] &= R_MASK_HIGH_4;
			key[7] &= R_MASK_HIGH_4;
			key[11] &= R_MASK_HIGH_4;
			key[15] &= R_MASK_HIGH_4;

			/*
			 * r[4], r[8], r[12] have bottom two bits clear (i.e., are in {0, 4, 8, . . . , 252}).
			 */
			key[4] &= R_MASK_LOW_2;
			key[8] &= R_MASK_LOW_2;
			key[12] &= R_MASK_LOW_2;
		}

		/// <summary>
		/// Checks a 32 byte key for compliance with the Poly1305 key requirements, e.g.
		/// <code>k[0] ... k[15], r[0] ... r[15]</code> with the required bits in <code>r</code> cleared
		/// as per <seealso cref="#clamp(byte[])"/>.
		/// </summary>
		/// <exception cref="IllegalArgumentException"> if the key is of the wrong length, or has invalid bits set
		///             in the <code>r</code> portion of the key. </exception>
		public static void checkKey(byte[] key)
		{
			if (key.Length != 32)
			{
				throw new IllegalArgumentException("Poly1305 key must be 256 bits.");
			}

			checkMask(key[3], R_MASK_HIGH_4);
			checkMask(key[7], R_MASK_HIGH_4);
			checkMask(key[11], R_MASK_HIGH_4);
			checkMask(key[15], R_MASK_HIGH_4);

			checkMask(key[4], R_MASK_LOW_2);
			checkMask(key[8], R_MASK_LOW_2);
			checkMask(key[12], R_MASK_LOW_2);
		}

		private static void checkMask(byte b, byte mask)
		{
			if ((b & (~mask)) != 0)
			{
				throw new IllegalArgumentException("Invalid format for r portion of Poly1305 key.");
			}
		}

	}
}
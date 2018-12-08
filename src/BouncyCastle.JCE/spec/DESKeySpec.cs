namespace javax.crypto.spec
{

	/// <summary>
	/// This class specifies a DES key.
	/// </summary>
	public class DESKeySpec : KeySpec
	{
		public const int DES_KEY_LEN = 8;

		private byte[] keyBytes = new byte[DES_KEY_LEN];

		/// <summary>
		/// Uses the first 8 bytes in <code>key</code> as the key material for the DES key.
		/// <para>
		/// The bytes that constitute the DES key are those between
		/// <code>key[0]</code> and <code>key[7]</code> inclusive.
		/// 
		/// </para>
		/// </summary>
		/// <param name="key"> - the buffer with the DES key material. </param>
		/// <exception cref="InvalidKeyException"> - if the given key material is shorter than 8 bytes. </exception>
		public DESKeySpec(byte[] key)
		{
			if (key.Length < DES_KEY_LEN)
			{
				throw new InvalidKeyException("DES key material too short in construction");
			}

			JavaSystem.arraycopy(key, 0, keyBytes, 0, keyBytes.Length);
		}

		/// <summary>
		/// Uses the first 8 bytes in <code>key</code>, beginning at
		/// <code>offset</code> inclusive, as the key material for the DES key.
		/// <para>
		/// The bytes that constitute the DES key are those between
		/// <code>key[offset]</code> and <code>key[offset+7]</code> inclusive.
		/// 
		/// </para>
		/// </summary>
		/// <param name="key"> the buffer with the DES key material. </param>
		/// <param name="offset"> the offset in <code>key</code>, where the DES key material starts. </param>
		/// <exception cref="InvalidKeyException"> if the given key material, starting at
		/// <code>offset</code> inclusive, is shorter than 8 bytes. </exception>
		public DESKeySpec(byte[] key, int offset)
		{
			if ((key.Length - offset) < DES_KEY_LEN)
			{
				throw new InvalidKeyException("DES key material too short in construction");
			}

			JavaSystem.arraycopy(key, offset, keyBytes, 0, keyBytes.Length);
		}

		/// <summary>
		/// Returns the DES key material.
		/// </summary>
		/// <returns> the DES key material. </returns>
		public virtual byte[] getKey()
		{
			byte[] tmp = new byte[DES_KEY_LEN];

			JavaSystem.arraycopy(keyBytes, 0, tmp, 0, tmp.Length);

			return tmp;
		}

		/// <summary>
		/// Checks if the given DES key material, starting at <code>offset</code>
		/// inclusive, is parity-adjusted.
		/// </summary>
		/// <param name="key"> the buffer with the DES key material. </param>
		/// <param name="offset"> the offset in <code>key</code>, where the DES key material starts.
		/// @returns true if the given DES key material is parity-adjusted, false otherwise. </param>
		/// <exception cref="InvalidKeyException"> if the given key material, starting at <code>offset</code>
		/// inclusive, is shorter than 8 bytes. </exception>
		public static bool isParityAdjusted(byte[] key, int offset)
		{
			if ((key.Length - offset) < DES_KEY_LEN)
			{
				throw new InvalidKeyException("key material too short in DESKeySpec.isParityAdjusted");
			}

			for (int i = 0; i < DES_KEY_LEN; i++)
			{
				byte keyByte = key[i + offset];
				int count = 0;

				keyByte = (byte)((keyByte & 0xff) >> 1);

				while (keyByte != 0)
				{
					/*
					 * we increment for every "on" bit
					 */
					if ((keyByte & 0x01) != 0)
					{
						count++;
					}

					keyByte = (byte)((keyByte & 0xff) >> 1);
				}

				if ((count & 1) == 1)
				{
					if ((key[i + offset] & 1) == 1)
					{
						return false;
					}
				}
				else if ((key[i + offset] & 1) != 1)
				{
					return false;
				}
			}

			return true;
		}

		/*
		 * Table of weak and semi-weak keys taken from Schneier pp281
		 */
		private const int N_DES_WEAK_KEYS = 16;

		private static byte[] DES_weak_keys = new byte[] {(byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x1f, (byte)0x1f, (byte)0x1f, (byte)0x1f, (byte)0x0e, (byte)0x0e, (byte)0x0e, (byte)0x0e, unchecked((byte)0xe0), unchecked((byte)0xe0), unchecked((byte)0xe0), unchecked((byte)0xe0), unchecked((byte)0xf1), unchecked((byte)0xf1), unchecked((byte)0xf1), unchecked((byte)0xf1), unchecked((byte)0xfe), unchecked((byte)0xfe), unchecked((byte)0xfe), unchecked((byte)0xfe), unchecked((byte)0xfe), unchecked((byte)0xfe), unchecked((byte)0xfe), unchecked((byte)0xfe), (byte)0x01, unchecked((byte)0xfe), (byte)0x01, unchecked((byte)0xfe), (byte)0x01, unchecked((byte)0xfe), (byte)0x01, unchecked((byte)0xfe), (byte)0x1f, unchecked((byte)0xe0), (byte)0x1f, unchecked((byte)0xe0), (byte)0x0e, unchecked((byte)0xf1), (byte)0x0e, unchecked((byte)0xf1), (byte)0x01, unchecked((byte)0xe0), (byte)0x01, unchecked((byte)0xe0), (byte)0x01, unchecked((byte)0xf1), (byte)0x01, unchecked((byte)0xf1), (byte)0x1f, unchecked((byte)0xfe), (byte)0x1f, unchecked((byte)0xfe), (byte)0x0e, unchecked((byte)0xfe), (byte)0x0e, unchecked((byte)0xfe), (byte)0x01, (byte)0x1f, (byte)0x01, (byte)0x1f, (byte)0x01, (byte)0x0e, (byte)0x01, (byte)0x0e, unchecked((byte)0xe0), unchecked((byte)0xfe), unchecked((byte)0xe0), unchecked((byte)0xfe), unchecked((byte)0xf1), unchecked((byte)0xfe), unchecked((byte)0xf1), unchecked((byte)0xfe), unchecked((byte)0xfe), (byte)0x01, unchecked((byte)0xfe), (byte)0x01, unchecked((byte)0xfe), (byte)0x01, unchecked((byte)0xfe), (byte)0x01, unchecked((byte)0xe0), (byte)0x1f, unchecked((byte)0xe0), (byte)0x1f, unchecked((byte)0xf1), (byte)0x0e, unchecked((byte)0xf1), (byte)0x0e, unchecked((byte)0xe0), (byte)0x01, unchecked((byte)0xe0), (byte)0x01, unchecked((byte)0xf1), (byte)0x01, unchecked((byte)0xf1), (byte)0x01, unchecked((byte)0xfe), (byte)0x1f, unchecked((byte)0xfe), (byte)0x1f, unchecked((byte)0xfe), (byte)0x0e, unchecked((byte)0xfe), (byte)0x0e, (byte)0x1f, (byte)0x01, (byte)0x1f, (byte)0x01, (byte)0x0e, (byte)0x01, (byte)0x0e, (byte)0x01, unchecked((byte)0xfe), unchecked((byte)0xe0), unchecked((byte)0xfe), unchecked((byte)0xe0), unchecked((byte)0xfe), unchecked((byte)0xf1), unchecked((byte)0xfe), unchecked((byte)0xf1)};

		/// <summary>
		/// Checks if the given DES key material is weak or semi-weak.
		/// </summary>
		/// <param name="key"> the buffer with the DES key material. </param>
		/// <param name="offset"> the offset in <code>key</code>, where the DES key
		/// material starts. </param>
		/// <returns> true if the given DES key material is weak or semi-weak, false otherwise. </returns>
		/// <exception cref="InvalidKeyException"> if the given key material, starting at <code>offset</code>
		/// inclusive, is shorter than 8 bytes. </exception>
		public static bool isWeak(byte[] key, int offset)
		{
			if (key.Length - offset < DES_KEY_LEN)
			{
				throw new InvalidKeyException("key material too short in DESKeySpec.isWeak");
			}

			for (int i = 0; i < N_DES_WEAK_KEYS; i++)
			{
				for (int j = 0; j < DES_KEY_LEN; j++)
				{
					if (key[j + offset] != DES_weak_keys[i * DES_KEY_LEN + j])
					{
						goto nextkeyContinue;
					}
				}

				return true;
				nextkeyContinue:;
			}
			nextkeyBreak:
			return false;
		}
	}

}
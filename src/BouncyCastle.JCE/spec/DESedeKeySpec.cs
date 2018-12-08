namespace javax.crypto.spec
{

	/// <summary>
	/// This class specifies a DES-EDE ("triple-DES") key.
	/// </summary>
	public class DESedeKeySpec : KeySpec
	{
		public const int DES_EDE_KEY_LEN = 24;

		private byte[] keyBytes = new byte[DES_EDE_KEY_LEN];

		/// <summary>
		/// Uses the first 24 bytes in <code>key</code> as the DES-EDE key.
		/// <para>
		/// The bytes that constitute the DES-EDE key are those between
		/// <code>key[0]</code> and <code>key[23]</code> inclusive
		/// 
		/// </para>
		/// </summary>
		/// <param name="key"> the buffer with the DES-EDE key material. </param>
		/// <exception cref="InvalidKeyException"> if the given key material is shorter
		/// than 24 bytes. </exception>
		public DESedeKeySpec(byte[] key)
		{
			if (key.Length < DES_EDE_KEY_LEN)
			{
				throw new InvalidKeyException("DESede key material too short in construction");
			}

			JavaSystem.arraycopy(key, 0, keyBytes, 0, keyBytes.Length);
		}

		/// <summary>
		/// Uses the first 24 bytes in <code>key</code>, beginning at
		/// <code>offset</code> inclusive, as the DES-EDE key.
		/// <para>
		/// The bytes that constitute the DES-EDE key are those between
		/// <code>key[offset]</code> and <code>key[offset+23]</code> inclusive.
		/// </para>
		/// </summary>
		/// <param name="key"> the buffer with the DES-EDE key material. </param>
		/// <param name="offset"> the offset in <code>key</code>, where the DES-EDE key
		/// material starts. </param>
		/// <exception cref="InvalidKeyException"> if the given key material, starting at
		/// <code>offset</code> inclusive, is shorter than 24 bytes </exception>
		public DESedeKeySpec(byte[] key, int offset)
		{
			if ((key.Length - offset) < DES_EDE_KEY_LEN)
			{
				throw new InvalidKeyException("DESede key material too short in construction");
			}

			JavaSystem.arraycopy(key, 0, keyBytes, 0, keyBytes.Length);
		}

		/// <summary>
		/// Returns the DES-EDE key.
		/// </summary>
		/// <returns> the DES-EDE key </returns>
		public virtual byte[] getKey()
		{
			byte[] tmp = new byte[DES_EDE_KEY_LEN];

			JavaSystem.arraycopy(keyBytes, 0, tmp, 0, tmp.Length);

			return tmp;
		}

		/// <summary>
		/// Checks if the given DES-EDE key, starting at <code>offset</code>
		/// inclusive, is parity-adjusted.
		/// </summary>
		/// <returns> true if the given DES-EDE key is parity-adjusted, false
		/// otherwise </returns>
		/// <exception cref="InvalidKeyException"> if the given key material, starting at
		/// <code>offset</code> inclusive, is shorter than 24 bytes </exception>
		public static bool isParityAdjusted(byte[] key, int offset)
		{
			if ((key.Length - offset) < DES_EDE_KEY_LEN)
			{
				throw new InvalidKeyException("key material too short in DESedeKeySpec.isParityAdjusted");
			}

			return (DESKeySpec.isParityAdjusted(key, offset) && DESKeySpec.isParityAdjusted(key, offset + 8) && DESKeySpec.isParityAdjusted(key, offset + 16));
		}
	}

}
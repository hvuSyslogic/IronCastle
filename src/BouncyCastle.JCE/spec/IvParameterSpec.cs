namespace javax.crypto.spec
{

	/// <summary>
	/// This class specifies an <i>initialization vector</i> (IV). IVs are used
	/// by ciphers in feedback mode, e.g., DES in CBC mode.
	/// </summary>
	public class IvParameterSpec : AlgorithmParameterSpec
	{
		private byte[] iv;

		/// <summary>
		/// Uses the bytes in <code>iv</code> as the IV.
		/// </summary>
		/// <param name="iv"> the buffer with the IV </param>
		public IvParameterSpec(byte[] iv)
		{
			if (iv == null)
			{
				throw new IllegalArgumentException("null iv passed");
			}

			this.iv = new byte[iv.Length];

			JavaSystem.arraycopy(iv, 0, this.iv, 0, iv.Length);
		}

		/// <summary>
		/// Uses the first <code>len</code> bytes in <code>iv</code>,
		/// beginning at <code>offset</code> inclusive, as the IV.
		/// <para>
		/// The bytes that constitute the IV are those between
		/// <code>iv[offset]</code> and <code>iv[offset+len-1]</code> inclusive.
		/// 
		/// </para>
		/// </summary>
		/// <param name="iv"> the buffer with the IV </param>
		/// <param name="offset"> the offset in <code>iv</code> where the IV starts </param>
		/// <param name="len"> the number of IV bytes </param>
		public IvParameterSpec(byte[] iv, int offset, int len)
		{
			if (iv == null)
			{
				throw new IllegalArgumentException("Null iv passed");
			}

			if (offset < 0 || len < 0 || (iv.Length - offset) < len)
			{
				throw new IllegalArgumentException("Bad offset/len");
			}

			this.iv = new byte[len];

			JavaSystem.arraycopy(iv, offset, this.iv, 0, len);
		}

		/// <summary>
		/// Returns the initialization vector (IV).
		/// </summary>
		/// <returns> the initialization vector (IV) </returns>
		public virtual byte[] getIV()
		{
			byte[] tmp = new byte[iv.Length];

			JavaSystem.arraycopy(iv, 0, tmp, 0, iv.Length);
			return tmp;
		}
	}

}
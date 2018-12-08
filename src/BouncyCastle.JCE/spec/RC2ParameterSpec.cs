namespace javax.crypto.spec
{

	/// <summary>
	/// This class specifies the parameters used with the
	/// <a href="http://www.rsa.com/rsalabs/newfaq/q75.html"><i>RC2</i></a>
	/// algorithm.
	/// <para>
	/// The parameters consist of an effective key size and optionally
	/// an 8-byte initialization vector (IV) (only in feedback mode).
	/// </para>
	/// <para>
	/// This class can be used to initialize a <code>Cipher</code> object that
	/// implements the <i>RC2</i> algorithm.
	/// </para>
	/// </summary>
	public class RC2ParameterSpec : AlgorithmParameterSpec
	{
		private int effectiveKeyBits;
		private byte[] iv = new byte[8];

		/// <summary>
		/// Constructs a parameter set for RC2 from the given effective key size
		/// (in bits).
		/// </summary>
		/// <param name="effectiveKeyBits"> the effective key size in bits. </param>
		public RC2ParameterSpec(int effectiveKeyBits)
		{
			this.effectiveKeyBits = effectiveKeyBits;
		}

		/// <summary>
		/// Constructs a parameter set for RC2 from the given effective key size
		/// (in bits) and an 8-byte IV.
		/// <para>
		/// The bytes that constitute the IV are those between
		/// <code>iv[0]</code> and <code>iv[7]</code> inclusive.
		/// 
		/// </para>
		/// </summary>
		/// <param name="effectiveKeyBits"> the effective key size in bits. </param>
		/// <param name="iv"> the buffer with the 8-byte IV. </param>
		public RC2ParameterSpec(int effectiveKeyBits, byte[] iv) : this(effectiveKeyBits, iv, 0)
		{
		}

		/// <summary>
		/// Constructs a parameter set for RC2 from the given effective key size
		///  (in bits) and IV.
		/// <para>
		/// The IV is taken from <code>iv</code>, starting at
		/// <code>offset</code> inclusive.
		/// The bytes that constitute the IV are those between
		/// <code>iv[offset]</code> and <code>iv[offset+7]</code> inclusive.
		/// 
		/// </para>
		/// </summary>
		/// <param name="effectiveKeyBits"> the effective key size in bits. </param>
		/// <param name="iv"> the buffer with the IV. </param>
		/// <param name="offset"> the offset in <code>iv</code> where the 8-byte IV starts. </param>
		public RC2ParameterSpec(int effectiveKeyBits, byte[] iv, int offset)
		{
			this.effectiveKeyBits = effectiveKeyBits;

			this.iv = new byte[8];
			JavaSystem.arraycopy(iv, offset, this.iv, 0, this.iv.Length);
		}

		/// <summary>
		/// Returns the effective key size in bits.
		/// </summary>
		/// <returns> the effective key size in bits. </returns>
		public virtual int getEffectiveKeyBits()
		{
			return effectiveKeyBits;
		}

		/// <summary>
		/// Returns the IV or null if this parameter set does not contain an IV.
		/// </summary>
		/// <returns> the IV or null if this parameter set does not contain an IV. </returns>
		public virtual byte[] getIV()
		{
			if (iv == null)
			{
				return null;
			}

			byte[] tmp = new byte[iv.Length];

			JavaSystem.arraycopy(iv, 0, tmp, 0, tmp.Length);

			return tmp;
		}

		/// <summary>
		/// Tests for equality between the specified object and this
		/// object. Two RC2ParameterSpec objects are considered equal if their 
		/// effective key sizes and IVs are equal.
		/// (Two IV references are considered equal if both are <tt>null</tt>.)
		/// </summary>
		/// <param name="obj"> the object to test for equality with this object. </param>
		/// <returns> true if the objects are considered equal, false otherwise.
		/// @override equals in class java.lang.Object </returns>
		public override bool Equals(object obj)
		{
			if ((obj == null) || !(obj is RC2ParameterSpec))
			{
				return false;
			}

			RC2ParameterSpec spec = (RC2ParameterSpec)obj;

			if (this.effectiveKeyBits != spec.effectiveKeyBits)
			{
				return false;
			}

			if (iv != null)
			{
				if (spec.iv == null)
				{
					return false;
				}

				for (int i = 0; i != iv.Length; i++)
				{
					if (iv[i] != spec.iv[i])
					{
						return false;
					}
				}
			}
			else if (spec.iv != null)
			{
				return false;
			}

			return true;
		}

		/// <summary>
		/// Calculates a hash code value for the object.
		/// Objects that are equal will also have the same hashcode.
		/// 
		/// @override hashCode in class java.lang.Object
		/// </summary>
		public override int GetHashCode()
		{
			throw new RuntimeException("Not yet implemented");
		}
	}

}
namespace javax.crypto.spec
{

	/// <summary>
	/// This class specifies the parameters used with the
	///  <a href="http://www.rsa.com/rsalabs/newfaq/q76.html"><i>RC5</i></a>
	///  algorithm.
	///  <para>
	///  The parameters consist of a version number, a rounds count, a word
	///  size, and optionally an initialization vector (IV) (only in feedback mode).
	/// </para>
	///  <para>
	///  This class can be used to initialize a <code>Cipher</code> object that
	///  implements the <i>RC5</i> algorithm as supplied by
	///  <a href="http://www.rsa.com">RSA Data Security, Inc.</a> (RSA DSI),
	///  or any parties authorized by RSA DSI.
	/// </para>
	/// </summary>
	public class RC5ParameterSpec : AlgorithmParameterSpec
	{
		private int version;
		private int rounds;
		private int wordSize;

		private byte[] iv;

		/// <summary>
		/// Constructs a parameter set for RC5 from the given version, number of
		/// rounds and word size (in bits).
		/// </summary>
		/// <param name="version"> the version. </param>
		/// <param name="rounds"> the number of rounds. </param>
		/// <param name="wordSize"> the word size in bits. </param>
		public RC5ParameterSpec(int version, int rounds, int wordSize)
		{
			this.version = version;
			this.rounds = rounds;
			this.wordSize = wordSize;
			this.iv = null;
		}

		/// <summary>
		/// Constructs a parameter set for RC5 from the given version, number of
		/// rounds, word size (in bits), and IV.
		/// <para>
		/// Note that the size of the IV (block size) must be twice the word
		/// size. The bytes that constitute the IV are those between
		/// <code>iv[0]</code> and <code>iv[2*(wordSize/8)-1]</code> inclusive.
		/// 
		/// </para>
		/// </summary>
		/// <param name="version"> the version. </param>
		/// <param name="rounds"> the number of rounds. </param>
		/// <param name="wordSize"> the word size in bits. </param>
		/// <param name="iv"> the buffer with the IV. </param>
		public RC5ParameterSpec(int version, int rounds, int wordSize, byte[] iv) : this(version, rounds, wordSize, iv, 0)
		{
		}

		/// <summary>
		/// Constructs a parameter set for RC5 from the given version, number of
		/// rounds, word size (in bits), and IV.
		/// <para>
		/// The IV is taken from <code>iv</code>, starting at <code>offset</code> inclusive.
		/// Note that the size of the IV (block size), starting at
		/// <code>offset</code> inclusive, must be twice the word size.
		/// The bytes that constitute the IV are those between
		/// <code>iv[offset]</code> and <code>iv[offset+2*(wordSize/8)-1]</code>
		/// inclusive.
		/// 
		/// </para>
		/// </summary>
		/// <param name="version"> the version. </param>
		/// <param name="rounds"> the number of rounds. </param>
		/// <param name="wordSize"> the word size in bits. </param>
		/// <param name="iv"> the buffer with the IV. </param>
		/// <param name="offset"> the offset in <code>iv</code> where the IV starts. </param>
		public RC5ParameterSpec(int version, int rounds, int wordSize, byte[] iv, int offset)
		{
			this.version = version;
			this.rounds = rounds;
			this.wordSize = wordSize;
			this.iv = new byte[2 * (wordSize / 8)];

			JavaSystem.arraycopy(iv, offset, this.iv, 0, this.iv.Length);
		}

		/// <summary>
		/// Returns the version.
		/// </summary>
		/// <returns> the version. </returns>
		public virtual int getVersion()
		{
			return version;
		}

		/// <summary>
		/// Returns the number of rounds.
		/// </summary>
		/// <returns> the number of rounds. </returns>
		public virtual int getRounds()
		{
			return rounds;
		}

		/// <summary>
		/// Returns the word size in bits
		/// </summary>
		/// <returns> the word size in bits. </returns>
		public virtual int getWordSize()
		{
			return wordSize;
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

			JavaSystem.arraycopy(iv, 0, tmp, 0, iv.Length);

			return tmp;
		}

		/// <summary>
		/// Tests for equality between the specified object and this
		/// object. Two RC5ParameterSpec objects are considered equal if their 
		/// version numbers, number of rounds, word sizes, and IVs are equal.
		/// (Two IV references are considered equal if both are <tt>null</tt>.)
		/// </summary>
		/// <param name="obj"> the object to test for equality with this object. </param>
		/// <returns> true if the objects are considered equal, false otherwise. </returns>
		public override bool Equals(object obj)
		{
			if ((obj == null) || !(obj is RC5ParameterSpec))
			{
				return false;
			}

			RC5ParameterSpec spec = (RC5ParameterSpec)obj;

			if (this.version != spec.version)
			{
				return false;
			}

			if (this.rounds != spec.rounds)
			{
				return false;
			}

			if (this.wordSize != spec.wordSize)
			{
				return false;
			}

			if (iv != null)
			{
				if (spec.iv == null || spec.iv.Length != iv.Length)
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
		/// </summary>
		public override int GetHashCode()
		{
			int code = version ^ rounds ^ wordSize;

			if (iv != null)
			{
				for (int i = 0; i != iv.Length; i++)
				{
					code ^= iv[i] << (8 * (i % 4));
				}
			}

			return code;
		}
	}

}
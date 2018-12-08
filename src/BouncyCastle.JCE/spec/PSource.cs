namespace javax.crypto.spec
{
	/// <summary>
	/// This class specifies the source for encoding input P in OAEP Padding, as
	/// defined in the <seealso cref="http://www.ietf.org/rfc/rfc3447.txt PKCS #1"/> standard.
	/// 
	/// <pre>
	/// 
	///  PKCS1PSourceAlgorithms    ALGORITHM-IDENTIFIER ::= {
	///  { OID id-pSpecified PARAMETERS OCTET STRING },
	///  ...  -- Allows for future expansion --
	///  }
	/// </pre>
	/// </summary>
	public class PSource
	{
		/// <summary>
		/// This class is used to explicitly specify the value for encoding input P
		/// in OAEP Padding.
		/// 
		/// </summary>
		public sealed class PSpecified : PSource
		{
			internal byte[] p;

			/// <summary>
			/// The encoding input P whose value equals byte[0].
			/// </summary>
			public static readonly PSpecified DEFAULT = new PSpecified(new byte[0]);

			/// <summary>
			/// Constructs the source explicitly with the specified value p as the
			/// encoding input P.
			/// </summary>
			/// <param name="p"> the value of the encoding input. The contents of the array
			///            are copied to protect against subsequent modification. </param>
			/// <exception cref="NullPointerException"> if p is null. </exception>
			public PSpecified(byte[] p) : base("PSpecified")
			{
				if (p == null)
				{
					throw new NullPointerException("The encoding input is null");
				}
				this.p = copyOf(p);
			}

			/// <summary>
			/// Returns the value of encoding input P.
			/// </summary>
			/// <returns> the value of encoding input P. A new array is returned each
			///         time this method is called. </returns>
			public byte[] getValue()
			{
				return copyOf(p);
			}

			public byte[] copyOf(byte[] b)
			{
				byte[] tmp = new byte[b.Length];

				JavaSystem.arraycopy(b, 0, tmp, 0, b.Length);

				return tmp;
			}
		}

		private string pSrcName;

		/// <summary>
		/// Constructs a source of the encoding input P for OAEP padding as defined
		/// in the PKCS #1 standard using the specified PSource algorithm.
		/// </summary>
		/// <param name="pSrcName"> the algorithm for the source of the encoding input P. </param>
		/// <exception cref="NullPointerException"> if pSrcName is null. </exception>
		public PSource(string pSrcName)
		{
			if (string.ReferenceEquals(pSrcName, null))
			{
				throw new NullPointerException("pSrcName is null");
			}
			this.pSrcName = pSrcName;
		}

		/// <summary>
		/// Returns the PSource algorithm name.
		/// </summary>
		/// <returns> the PSource algorithm name. </returns>
		public virtual string getAlgorithm()
		{
			return pSrcName;
		}
	}

}
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.@params
{
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// Parameter class for the HKDFBytesGenerator class.
	/// </summary>
	public class HKDFParameters : DerivationParameters
	{
		private readonly byte[] ikm;
		private readonly bool skipExpand;
		private readonly byte[] salt;
		private readonly byte[] info;


		private HKDFParameters(byte[] ikm, bool skip, byte[] salt, byte[] info)
		{
			if (ikm == null)
			{
				throw new IllegalArgumentException("IKM (input keying material) should not be null");
			}

			this.ikm = Arrays.clone(ikm);

			this.skipExpand = skip;

			if (salt == null || salt.Length == 0)
			{
				this.salt = null;
			}
			else
			{
				this.salt = Arrays.clone(salt);
			}

			if (info == null)
			{
				this.info = new byte[0];
			}
			else
			{
				this.info = Arrays.clone(info);
			}
		}

		/// <summary>
		/// Generates parameters for HKDF, specifying both the optional salt and
		/// optional info. Step 1: Extract won't be skipped.
		/// </summary>
		/// <param name="ikm">  the input keying material or seed </param>
		/// <param name="salt"> the salt to use, may be null for a salt for hashLen zeros </param>
		/// <param name="info"> the info to use, may be null for an info field of zero bytes </param>

		public HKDFParameters(byte[] ikm, byte[] salt, byte[] info) : this(ikm, false, salt, info)
		{
		}

		/// <summary>
		/// Factory method that makes the HKDF skip the extract part of the key
		/// derivation function.
		/// </summary>
		/// <param name="ikm">  the input keying material or seed, directly used for step 2:
		///             Expand </param>
		/// <param name="info"> the info to use, may be null for an info field of zero bytes </param>
		/// <returns> HKDFParameters that makes the implementation skip step 1 </returns>

		public static HKDFParameters skipExtractParameters(byte[] ikm, byte[] info)
		{

			return new HKDFParameters(ikm, true, null, info);
		}


		public static HKDFParameters defaultParameters(byte[] ikm)
		{
			return new HKDFParameters(ikm, false, null, null);
		}

		/// <summary>
		/// Returns the input keying material or seed.
		/// </summary>
		/// <returns> the keying material </returns>
		public virtual byte[] getIKM()
		{
			return Arrays.clone(ikm);
		}

		/// <summary>
		/// Returns if step 1: extract has to be skipped or not
		/// </summary>
		/// <returns> true for skipping, false for no skipping of step 1 </returns>
		public virtual bool skipExtract()
		{
			return skipExpand;
		}

		/// <summary>
		/// Returns the salt, or null if the salt should be generated as a byte array
		/// of HashLen zeros.
		/// </summary>
		/// <returns> the salt, or null </returns>
		public virtual byte[] getSalt()
		{
			return Arrays.clone(salt);
		}

		/// <summary>
		/// Returns the info field, which may be empty (null is converted to empty).
		/// </summary>
		/// <returns> the info field, never null </returns>
		public virtual byte[] getInfo()
		{
			return Arrays.clone(info);
		}
	}

}
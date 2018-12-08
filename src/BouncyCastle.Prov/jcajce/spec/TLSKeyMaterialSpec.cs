namespace org.bouncycastle.jcajce.spec
{

	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// Key Spec class for generating TLS key/iv material.
	/// </summary>
	public class TLSKeyMaterialSpec : KeySpec
	{
		public const string MASTER_SECRET = "master secret";
		public const string KEY_EXPANSION = "key expansion";

		private readonly byte[] secret;
		private readonly string label;
		private readonly int length;
		private readonly byte[] seed;

		/// <summary>
		/// Constructor specifying the basic parameters for a TLS KDF
		/// </summary>
		/// <param name="secret"> secret to use </param>
		/// <param name="label"> e.g. 'master secret', or 'key expansion' </param>
		/// <param name="length"> number of bytes of material to be generated </param>
		/// <param name="seedMaterial"> array of seed material inputs (to be concatenated together) </param>
		public TLSKeyMaterialSpec(byte[] secret, string label, int length, params byte[][] seedMaterial)
		{
			this.secret = Arrays.clone(secret);
			this.label = label;
			this.length = length;
			this.seed = Arrays.concatenate(seedMaterial);
		}

		/// <summary>
		/// Return the label associated with this spec.
		/// </summary>
		/// <returns> the label to be used with the TLS KDF. </returns>
		public virtual string getLabel()
		{
			return label;
		}

		/// <summary>
		/// Return the number of bytes of key material to be generated for this spec.
		/// </summary>
		/// <returns> the length in bytes of the result. </returns>
		public virtual int getLength()
		{
			return length;
		}

		/// <summary>
		/// Return the secret associated with this spec.
		/// </summary>
		/// <returns> a copy of the secret. </returns>
		public virtual byte[] getSecret()
		{
			return Arrays.clone(secret);
		}

		/// <summary>
		/// Return the full seed for the spec.
		/// </summary>
		/// <returns> a copy of the seed. </returns>
		public virtual byte[] getSeed()
		{
			return Arrays.clone(seed);
		}
	}

}
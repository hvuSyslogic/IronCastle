namespace org.bouncycastle.pqc.jcajce.spec
{

	/// <summary>
	/// Key generation spec for SPHINCS-256 to allow specifying of tree hash.
	/// </summary>
	public class SPHINCS256KeyGenParameterSpec : AlgorithmParameterSpec
	{
		/// <summary>
		/// Use SHA512-256 for the tree generation function.
		/// </summary>
		public const string SHA512_256 = "SHA512-256";

		/// <summary>
		/// Use SHA3-256 for the tree generation function.
		/// </summary>
		public const string SHA3_256 = "SHA3-256";

		private readonly string treeHash;

		/// <summary>
		/// Default constructor SHA512-256
		/// </summary>
		public SPHINCS256KeyGenParameterSpec() : this(SHA512_256)
		{
		}

		/// <summary>
		/// Specify the treehash, one of SHA512-256, or SHA3-256.
		/// </summary>
		/// <param name="treeHash"> the hash for building the public key tree. </param>
		public SPHINCS256KeyGenParameterSpec(string treeHash)
		{
			this.treeHash = treeHash;
		}

		public virtual string getTreeDigest()
		{
			return treeHash;
		}
	}

}
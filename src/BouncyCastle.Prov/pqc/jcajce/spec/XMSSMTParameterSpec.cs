namespace org.bouncycastle.pqc.jcajce.spec
{

	public class XMSSMTParameterSpec : AlgorithmParameterSpec
	{
		/// <summary>
		/// Use SHA-256 for the tree generation function.
		/// </summary>
		public const string SHA256 = "SHA256";

		/// <summary>
		/// Use SHA512 for the tree generation function.
		/// </summary>
		public const string SHA512 = "SHA512";

		/// <summary>
		/// Use SHAKE128 for the tree generation function.
		/// </summary>
		public const string SHAKE128 = "SHAKE128";

		/// <summary>
		/// Use SHAKE256 for the tree generation function.
		/// </summary>
		public const string SHAKE256 = "SHAKE256";

		private readonly int height;
		private readonly int layers;
		private readonly string treeDigest;

		public XMSSMTParameterSpec(int height, int layers, string treeDigest)
		{
			this.height = height;
			this.layers = layers;
			this.treeDigest = treeDigest;
		}

		public virtual string getTreeDigest()
		{
			return treeDigest;
		}

		public virtual int getHeight()
		{
			return height;
		}

		public virtual int getLayers()
		{
			return layers;
		}
	}

}
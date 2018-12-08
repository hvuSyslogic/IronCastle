namespace org.bouncycastle.jcajce.spec
{

	/// <summary>
	/// A simple object to indicate that a symmetric cipher should reuse the
	/// last key provided.
	/// </summary>
	public class RepeatedSecretKeySpec : SecretKey
	{
		private string algorithm;

		public RepeatedSecretKeySpec(string algorithm)
		{
			this.algorithm = algorithm;
		}

		public virtual string getAlgorithm()
		{
			return algorithm;
		}

		public virtual string getFormat()
		{
			return null;
		}

		public virtual byte[] getEncoded()
		{
			return null;
		}
	}

}
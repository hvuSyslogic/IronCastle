using org.bouncycastle.jcajce.spec;

namespace org.bouncycastle.jce.spec
{
	/// <summary>
	/// A simple object to indicate that a symmetric cipher should reuse the
	/// last key provided. </summary>
	/// @deprecated use super class org.bouncycastle.jcajce.spec.RepeatedSecretKeySpec 
	public class RepeatedSecretKeySpec : RepeatedSecretKeySpec
	{
		private string algorithm;

		public RepeatedSecretKeySpec(string algorithm) : base(algorithm)
		{
		}
	}

}
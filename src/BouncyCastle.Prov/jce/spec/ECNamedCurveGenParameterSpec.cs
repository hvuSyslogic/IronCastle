namespace org.bouncycastle.jce.spec
{

	/// <summary>
	/// Named curve generation spec
	/// <para>
	/// If you are using JDK 1.5 you should be looking at ECGenParameterSpec.
	/// </para>
	/// </summary>
	public class ECNamedCurveGenParameterSpec : AlgorithmParameterSpec
	{
		private string name;

		public ECNamedCurveGenParameterSpec(string name)
		{
			this.name = name;
		}

		/// <summary>
		/// return the name of the curve the EC domain parameters belong to.
		/// </summary>
		public virtual string getName()
		{
			return name;
		}
	}

}
using org.bouncycastle.jcajce.spec;

namespace org.bouncycastle.jce.spec
{
	/// <summary>
	/// A parameter spec for the GOST-28147 cipher. </summary>
	/// @deprecated use  org.bouncycastle.jcajce.spec.GOST28147ParameterSpec 
	public class GOST28147ParameterSpec : GOST28147ParameterSpec
	{
		/// <summary>
		/// @deprecated
		/// </summary>
		public GOST28147ParameterSpec(byte[] sBox) : base(sBox)
		{
		}

		/// <summary>
		/// @deprecated
		/// </summary>
		public GOST28147ParameterSpec(byte[] sBox, byte[] iv) : base(sBox, iv)
		{

		}

		/// <summary>
		/// @deprecated
		/// </summary>
		public GOST28147ParameterSpec(string sBoxName) : base(sBoxName)
		{
		}

		/// <summary>
		/// @deprecated
		/// </summary>
		public GOST28147ParameterSpec(string sBoxName, byte[] iv) : base(sBoxName, iv)
		{
		}
	}
}
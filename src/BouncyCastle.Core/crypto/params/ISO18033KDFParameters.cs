namespace org.bouncycastle.crypto.@params
{

	/// <summary>
	/// parameters for Key derivation functions for ISO-18033
	/// </summary>
	public class ISO18033KDFParameters : DerivationParameters
	{
		internal byte[] seed;

		public ISO18033KDFParameters(byte[] seed)
		{
			this.seed = seed;
		}

		public virtual byte[] getSeed()
		{
			return seed;
		}
	}

}
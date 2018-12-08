namespace org.bouncycastle.crypto.@params
{

	/// <summary>
	/// parameters for Key derivation functions for IEEE P1363a
	/// </summary>
	public class KDFParameters : DerivationParameters
	{
		internal byte[] iv;
		internal byte[] shared;

		public KDFParameters(byte[] shared, byte[] iv)
		{
			this.shared = shared;
			this.iv = iv;
		}

		public virtual byte[] getSharedSecret()
		{
			return shared;
		}

		public virtual byte[] getIV()
		{
			return iv;
		}
	}

}
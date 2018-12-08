using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.@params
{

	/// <summary>
	/// parameters for mask derivation functions.
	/// </summary>
	public class MGFParameters : DerivationParameters
	{
		internal byte[] seed;

		public MGFParameters(byte[] seed) : this(seed, 0, seed.Length)
		{
		}

		public MGFParameters(byte[] seed, int off, int len)
		{
			this.seed = new byte[len];
			JavaSystem.arraycopy(seed, off, this.seed, 0, len);
		}

		public virtual byte[] getSeed()
		{
			return seed;
		}
	}

}
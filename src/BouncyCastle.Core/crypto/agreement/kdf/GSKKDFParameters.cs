namespace org.bouncycastle.crypto.agreement.kdf
{

	/// <summary>
	/// BSI Key Derivation Function Parameters for Session Keys (see BSI-TR-03111 Section 4.3.3)
	/// </summary>
	public class GSKKDFParameters : DerivationParameters
	{
		private readonly byte[] z;
		private readonly int startCounter;
		private readonly byte[] nonce;

		public GSKKDFParameters(byte[] z, int startCounter) : this(z, startCounter, null)
		{
		}

		public GSKKDFParameters(byte[] z, int startCounter, byte[] nonce)
		{
			this.z = z;
			this.startCounter = startCounter;
			this.nonce = nonce;
		}

		public virtual byte[] getZ()
		{
			return z;
		}

		public virtual int getStartCounter()
		{
			return startCounter;
		}

		public virtual byte[] getNonce()
		{
			return nonce;
		}
	}

}
namespace org.bouncycastle.pqc.crypto.test
{

	/// <summary>
	/// Implementation of null PRNG returning zeroes only. For testing purposes
	/// only(!).
	/// </summary>
	public sealed class NullPRNG : SecureRandom
	{

		private const long serialVersionUID = 1L;

		public NullPRNG() : base()
		{
		}

		public void nextBytes(byte[] bytes)
		{
			for (int i = 0; i < bytes.Length; i++)
			{
				bytes[i] = 0x00;
			}
		}
	}

}
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.@params
{

	public class RC5Parameters : CipherParameters
	{
		private byte[] key;
		private int rounds;

		public RC5Parameters(byte[] key, int rounds)
		{
			if (key.Length > 255)
			{
				throw new IllegalArgumentException("RC5 key length can be no greater than 255");
			}

			this.key = new byte[key.Length];
			this.rounds = rounds;

			JavaSystem.arraycopy(key, 0, this.key, 0, key.Length);
		}

		public virtual byte[] getKey()
		{
			return key;
		}

		public virtual int getRounds()
		{
			return rounds;
		}
	}

}
using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.@params
{

	public class KeyParameter : CipherParameters
	{
		private byte[] key;

		public KeyParameter(byte[] key) : this(key, 0, key.Length)
		{
		}

		public KeyParameter(byte[] key, int keyOff, int keyLen)
		{
			this.key = new byte[keyLen];

			JavaSystem.arraycopy(key, keyOff, this.key, 0, keyLen);
		}

		public virtual byte[] getKey()
		{
			return key;
		}
	}

}
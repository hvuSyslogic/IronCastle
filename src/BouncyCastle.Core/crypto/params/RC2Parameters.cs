namespace org.bouncycastle.crypto.@params
{
	public class RC2Parameters : KeyParameter
	{
		private int bits;

		public RC2Parameters(byte[] key) : this(key, (key.Length > 128) ? 1024 : (key.Length * 8))
		{
		}

		public RC2Parameters(byte[] key, int bits) : base(key)
		{
			this.bits = bits;
		}

		public virtual int getEffectiveKeyBits()
		{
			return bits;
		}
	}

}
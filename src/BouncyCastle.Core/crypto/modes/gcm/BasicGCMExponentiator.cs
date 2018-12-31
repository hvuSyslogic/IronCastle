namespace org.bouncycastle.crypto.modes.gcm
{
	using Arrays = org.bouncycastle.util.Arrays;

	public class BasicGCMExponentiator : GCMExponentiator
	{
		private ulong[] x;

		public virtual void init(byte[] x)
		{
			this.x = GCMUtil.asLongs(x);
		}

		public virtual void exponentiateX(long pow, byte[] output)
		{
			// Initial value is little-endian 1
			ulong[] y = GCMUtil.oneAsLongs();

			if (pow > 0)
			{
				ulong[] powX = Arrays.clone(x);
				do
				{
					if ((pow & 1L) != 0)
					{
						GCMUtil.multiply(y, powX);
					}
					GCMUtil.square(powX, powX);
					pow = (long)((ulong)pow >> 1);
				} while (pow > 0);
			}

			GCMUtil.asBytes(y, output);
		}
	}

}
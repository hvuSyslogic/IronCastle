namespace org.bouncycastle.bcpg
{

	/// <summary>
	/// a multiple precision integer
	/// </summary>
	public class MPInteger : BCPGObject
	{
		internal BigInteger value = null;

		public MPInteger(BCPGInputStream @in)
		{
			int length = (@in.read() << 8) | @in.read();
			byte[] bytes = new byte[(length + 7) / 8];

			@in.readFully(bytes);

			value = new BigInteger(1, bytes);
		}

		public MPInteger(BigInteger value)
		{
			if (value == null || value.signum() < 0)
			{
				throw new IllegalArgumentException("value must not be null, or negative");
			}

			this.value = value;
		}

		public virtual BigInteger getValue()
		{
			return value;
		}

		public override void encode(BCPGOutputStream @out)
		{
			int length = value.bitLength();

			@out.write(length >> 8);
			@out.write(length);

			byte[] bytes = value.toByteArray();

			if (bytes[0] == 0)
			{
				@out.write(bytes, 1, bytes.Length - 1);
			}
			else
			{
				@out.write(bytes, 0, bytes.Length);
			}
		}
	}

}
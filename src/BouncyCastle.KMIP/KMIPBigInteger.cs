namespace org.bouncycastle.kmip.wire
{

	/// <summary>
	/// The KMIP BigInteger.
	/// </summary>
	public class KMIPBigInteger : KMIPItem<BigInteger>
	{
		private readonly int tag;
		private readonly BigInteger value;

		public KMIPBigInteger(int tag, BigInteger value)
		{
			this.tag = tag;
			this.value = value;
		}

		public virtual int getTag()
		{
			return tag;
		}

		public virtual byte getType()
		{
			return KMIPType.BIG_INTEGER;
		}

		public virtual long getLength()
		{
			int length = value.toByteArray().length;

			if (length % 8 == 0)
			{
				return length;
			}

			return length + (8 - (length % 8));
		}

		public virtual BigInteger getValue()
		{
			return value;
		}

		public virtual KMIPItem toKMIPItem()
		{
			return this;
		}
	}

}
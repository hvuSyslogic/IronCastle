namespace org.bouncycastle.kmip.wire
{
	public class KMIPLong : KMIPItem
	{
		private readonly int tag;
		private readonly long value;

		public KMIPLong(int tag, long value)
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
			return KMIPType.LONG_INTEGER;
		}

		public virtual long getLength()
		{
			return 8;
		}

		public virtual object getValue()
		{
			return new long?(value);
		}

		public virtual KMIPItem toKMIPItem()
		{
			return this;
		}
	}

}
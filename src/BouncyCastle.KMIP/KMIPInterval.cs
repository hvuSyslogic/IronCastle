namespace org.bouncycastle.kmip.wire
{
	public class KMIPInterval : KMIPItem
	{
		private readonly int tag;
		private readonly long value;

		public KMIPInterval(int tag, long value)
		{
			if (value > 0xffffffffL || value < 0)
			{
				throw new IllegalArgumentException("interval value out of range");
			}

			this.tag = tag;
			this.value = value;
		}

		public virtual int getTag()
		{
			return tag;
		}

		public virtual byte getType()
		{
			return KMIPType.INTERVAL;
		}

		public virtual long getLength()
		{
			return 4;
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
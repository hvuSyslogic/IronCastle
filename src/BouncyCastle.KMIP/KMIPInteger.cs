namespace org.bouncycastle.kmip.wire
{
	using Integers = org.bouncycastle.util.Integers;

	public class KMIPInteger : KMIPItem
	{
		private readonly int tag;
		private readonly int? value;

		public KMIPInteger(int tag, int value)
		{
			this.tag = tag;
			this.value = Integers.valueOf(value);
		}

		public virtual int getTag()
		{
			return tag;
		}

		public virtual byte getType()
		{
			return KMIPType.INTEGER;
		}

		public virtual long getLength()
		{
			return 4;
		}

		public virtual object getValue()
		{
			return value;
		}

		public virtual KMIPItem toKMIPItem()
		{
			return this;
		}
	}

}
namespace org.bouncycastle.kmip.wire
{
	public class KMIPBoolean : KMIPItem
	{
		private readonly int tag;
		private readonly bool value;

		public KMIPBoolean(int tag, bool value)
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
			return KMIPType.BOOLEAN;
		}

		public virtual long getLength()
		{
			return 8;
		}

		public virtual object getValue()
		{
			return value ? true : false;
		}

		public virtual KMIPItem toKMIPItem()
		{
			return this;
		}
	}

}
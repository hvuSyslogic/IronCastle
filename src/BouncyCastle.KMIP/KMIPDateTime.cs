using System;

namespace org.bouncycastle.kmip.wire
{

	public class KMIPDateTime : KMIPItem
	{
		private readonly int tag;
		private readonly long value;

		public KMIPDateTime(int tag, DateTime value)
		{
			this.tag = tag;
			this.value = value.Ticks;
		}

		public virtual int getTag()
		{
			return tag;
		}

		public virtual byte getType()
		{
			return KMIPType.DATE_TIME;
		}

		public virtual long getLength()
		{
			return 8;
		}

		public virtual object getValue()
		{
			return new DateTime(value);
		}

		public virtual KMIPItem toKMIPItem()
		{
			return this;
		}
	}

}
namespace org.bouncycastle.kmip.wire
{
	using Strings = org.bouncycastle.util.Strings;

	public class KMIPTextString : KMIPItem
	{
		private readonly int tag;
		private readonly string value;

		public KMIPTextString(int tag, string value)
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
			return KMIPType.TEXT_STRING;
		}

		public virtual long getLength()
		{
			return Strings.toUTF8ByteArray(value).Length;
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
namespace org.bouncycastle.kmip.wire
{
	using Arrays = org.bouncycastle.util.Arrays;

	public class KMIPByteString : KMIPItem
	{
		private readonly int tag;
		private readonly byte[] value;

		public KMIPByteString(int tag, byte[] value)
		{
			this.tag = tag;
			this.value = Arrays.clone(value);
		}

		public virtual int getTag()
		{
			return tag;
		}

		public virtual byte getType()
		{
			return KMIPType.BYTE_STRING;
		}

		public virtual long getLength()
		{
			return value.Length;
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
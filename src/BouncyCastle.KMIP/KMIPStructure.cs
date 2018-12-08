namespace org.bouncycastle.kmip.wire
{

	public class KMIPStructure : KMIPItem
	{
		private readonly int tag;
		private readonly KMIPItem[] items;

		public KMIPStructure(int tag, KMIPItem item)
		{
			this.tag = tag;
			this.items = new KMIPItem[] {item};
		}

		public KMIPStructure(int tag, KMIPItem[] items)
		{
			this.tag = tag;
			this.items = new KMIPItem[items.Length];
			JavaSystem.arraycopy(items, 0, this.items, 0, items.Length);
		}

		public KMIPStructure(int tag, List<KMIPItem> items)
		{
			this.tag = tag;
			this.items = (KMIPItem[])items.toArray(new KMIPItem[items.size()]);
		}

		public virtual int getTag()
		{
			return tag;
		}

		public virtual byte getType()
		{
			return KMIPType.STRUCTURE;
		}

		public virtual long getLength()
		{
			long totalLength = 0;

			for (int i = 0; i != items.Length; i++)
			{
				KMIPItem item = items[i];
				long length = item.getLength();

				totalLength += 8; // the header

				// the body
				if (length <= 8)
				{
					totalLength += 8;
				}
				else
				{
					if (length % 8 == 0)
					{
						totalLength += length;
					}
					else
					{
						totalLength += ((length / 8) + 1) * 8;
					}
				}
			}

			return totalLength;
		}

		public virtual List<KMIPItem> getValue()
		{
			return Collections.unmodifiableList(Arrays.asList(items));
		}

		public virtual KMIPItem toKMIPItem()
		{
			return this;
		}
	}

}
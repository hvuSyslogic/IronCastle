namespace org.bouncycastle.pqc.crypto.xmss
{
	using Pack = org.bouncycastle.util.Pack;

	/// <summary>
	/// L-tree address.
	/// 
	/// </summary>
	public sealed class LTreeAddress : XMSSAddress
	{

		private const int TYPE = 0x01;

		private readonly int lTreeAddress;
		private readonly int treeHeight;
		private readonly int treeIndex;

		private LTreeAddress(Builder builder) : base(builder)
		{
			lTreeAddress = builder.lTreeAddress;
			treeHeight = builder.treeHeight;
			treeIndex = builder.treeIndex;
		}

		public class Builder : XMSSAddress.Builder<Builder>
		{

			/* optional */
			internal int lTreeAddress = 0;
			internal int treeHeight = 0;
			internal int treeIndex = 0;

			public Builder() : base(TYPE)
			{
			}

			public virtual Builder withLTreeAddress(int val)
			{
				lTreeAddress = val;
				return this;
			}

			public virtual Builder withTreeHeight(int val)
			{
				treeHeight = val;
				return this;
			}

			public virtual Builder withTreeIndex(int val)
			{
				treeIndex = val;
				return this;
			}

			public override XMSSAddress build()
			{
				return new LTreeAddress(this);
			}

			public override Builder getThis()
			{
				return this;
			}
		}

		public override byte[] toByteArray()
		{
			byte[] byteRepresentation = base.toByteArray();
			Pack.intToBigEndian(lTreeAddress, byteRepresentation, 16);
			Pack.intToBigEndian(treeHeight, byteRepresentation, 20);
			Pack.intToBigEndian(treeIndex, byteRepresentation, 24);
			return byteRepresentation;
		}

		public int getLTreeAddress()
		{
			return lTreeAddress;
		}

		public int getTreeHeight()
		{
			return treeHeight;
		}

		public int getTreeIndex()
		{
			return treeIndex;
		}
	}

}
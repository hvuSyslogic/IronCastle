using org.bouncycastle.util;

namespace org.bouncycastle.pqc.crypto.xmss
{
	
	/// <summary>
	/// Hash tree address.
	/// </summary>
	public sealed class HashTreeAddress : XMSSAddress
	{

		private const int TYPE = 0x02;
		private const int PADDING = 0x00;

		private readonly int padding;
		private readonly int treeHeight;
		private readonly int treeIndex;

		private HashTreeAddress(Builder builder) : base(builder)
		{
			padding = PADDING;
			treeHeight = builder.treeHeight;
			treeIndex = builder.treeIndex;
		}

		public class Builder : XMSSAddress.Builder<Builder>
		{

			/* optional */
			internal int treeHeight = 0;
			internal int treeIndex = 0;

			public Builder() : base(TYPE)
			{
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
				return new HashTreeAddress(this);
			}

			public override Builder getThis()
			{
				return this;
			}
		}

		public override byte[] toByteArray()
		{
			byte[] byteRepresentation = base.toByteArray();
			Pack.intToBigEndian(padding, byteRepresentation,16);
			Pack.intToBigEndian(treeHeight, byteRepresentation, 20);
			Pack.intToBigEndian(treeIndex, byteRepresentation, 24);
			return byteRepresentation;
		}

		public int getPadding()
		{
			return padding;
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
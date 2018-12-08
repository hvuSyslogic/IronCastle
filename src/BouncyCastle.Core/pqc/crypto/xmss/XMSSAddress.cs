namespace org.bouncycastle.pqc.crypto.xmss
{
	using Pack = org.bouncycastle.util.Pack;

	/// <summary>
	/// XMSS address.
	/// </summary>
	public abstract class XMSSAddress
	{

		private readonly int layerAddress;
		private readonly long treeAddress;
		private readonly int type;
		private readonly int keyAndMask;

		public XMSSAddress(Builder builder)
		{
			layerAddress = builder.layerAddress;
			treeAddress = builder.treeAddress;
			type = builder.type;
			keyAndMask = builder.keyAndMask;
		}

		public abstract class Builder<T> where T : Builder
		{

			/* mandatory */
			internal readonly int type;
			/* optional */
			internal int layerAddress = 0;
			internal long treeAddress = 0L;
			internal int keyAndMask = 0;

			public Builder(int type) : base()
			{
				this.type = type;
			}

			public virtual T withLayerAddress(int val)
			{
				layerAddress = val;
				return getThis();
			}

			public virtual T withTreeAddress(long val)
			{
				treeAddress = val;
				return getThis();
			}

			public virtual T withKeyAndMask(int val)
			{
				keyAndMask = val;
				return getThis();
			}

			public abstract XMSSAddress build();

			public abstract T getThis();
		}

		public virtual byte[] toByteArray()
		{
			byte[] byteRepresentation = new byte[32];
			Pack.intToBigEndian(layerAddress, byteRepresentation, 0);
			Pack.longToBigEndian(treeAddress, byteRepresentation, 4);
			Pack.intToBigEndian(type, byteRepresentation, 12);
			Pack.intToBigEndian(keyAndMask, byteRepresentation, 28);
			return byteRepresentation;
		}

		public int getLayerAddress()
		{
			return layerAddress;
		}

		public long getTreeAddress()
		{
			return treeAddress;
		}

		public int getType()
		{
			return type;
		}

		public int getKeyAndMask()
		{
			return keyAndMask;
		}
	}

}
using org.bouncycastle.util;

namespace org.bouncycastle.pqc.crypto.xmss
{
	
	/// <summary>
	/// OTS hash address.
	/// </summary>
	public sealed class OTSHashAddress : XMSSAddress
	{

		private const int TYPE = 0x00;

		private readonly int otsAddress;
		private readonly int chainAddress;
		private readonly int hashAddress;

		private OTSHashAddress(Builder builder) : base(builder)
		{
			otsAddress = builder.otsAddress;
			chainAddress = builder.chainAddress;
			hashAddress = builder.hashAddress;
		}

		public class Builder : XMSSAddress.Builder<Builder>
		{

			/* optional */
			internal int otsAddress = 0;
			internal int chainAddress = 0;
			internal int hashAddress = 0;

			public Builder() : base(TYPE)
			{
			}

			public virtual Builder withOTSAddress(int val)
			{
				otsAddress = val;
				return this;
			}

			public virtual Builder withChainAddress(int val)
			{
				chainAddress = val;
				return this;
			}

			public virtual Builder withHashAddress(int val)
			{
				hashAddress = val;
				return this;
			}

			public override XMSSAddress build()
			{
				return new OTSHashAddress(this);
			}

			public override Builder getThis()
			{
				return this;
			}
		}

		public override byte[] toByteArray()
		{
			byte[] byteRepresentation = base.toByteArray();
			Pack.intToBigEndian(otsAddress, byteRepresentation,16);
			Pack.intToBigEndian(chainAddress, byteRepresentation, 20);
			Pack.intToBigEndian(hashAddress, byteRepresentation, 24);
			return byteRepresentation;
		}

		public int getOTSAddress()
		{
			return otsAddress;
		}

		public int getChainAddress()
		{
			return chainAddress;
		}

		public int getHashAddress()
		{
			return hashAddress;
		}
	}

}
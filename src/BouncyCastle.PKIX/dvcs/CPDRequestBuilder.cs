namespace org.bouncycastle.dvcs
{
	using DVCSRequestInformationBuilder = org.bouncycastle.asn1.dvcs.DVCSRequestInformationBuilder;
	using Data = org.bouncycastle.asn1.dvcs.Data;
	using ServiceType = org.bouncycastle.asn1.dvcs.ServiceType;

	/// <summary>
	/// Builder of DVCSRequests to CPD service (Certify Possession of Data).
	/// </summary>
	public class CPDRequestBuilder : DVCSRequestBuilder
	{
		public CPDRequestBuilder() : base(new DVCSRequestInformationBuilder(ServiceType.CPD))
		{
		}

		/// <summary>
		/// Build CPD request.
		/// </summary>
		/// <param name="messageBytes">  - data to be certified </param>
		/// <returns> a DVSCRequest based on the builder's current state and messageBytes. </returns>
		/// <exception cref="DVCSException"> on a build issue. </exception>
		public virtual DVCSRequest build(byte[] messageBytes)
		{
			Data data = new Data(messageBytes);

			return createDVCRequest(data);
		}
	}

}
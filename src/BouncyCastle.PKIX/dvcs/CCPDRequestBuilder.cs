namespace org.bouncycastle.dvcs
{
	using DVCSRequestInformationBuilder = org.bouncycastle.asn1.dvcs.DVCSRequestInformationBuilder;
	using Data = org.bouncycastle.asn1.dvcs.Data;
	using ServiceType = org.bouncycastle.asn1.dvcs.ServiceType;

	/// <summary>
	/// Builder of CCPD requests (Certify Claim of Possession of Data).
	/// </summary>
	public class CCPDRequestBuilder : DVCSRequestBuilder
	{
		public CCPDRequestBuilder() : base(new DVCSRequestInformationBuilder(ServiceType.CCPD))
		{
		}

		/// <summary>
		/// Builds CCPD request.
		/// </summary>
		/// <param name="messageImprint"> - the message imprint to include. </param>
		/// <returns> a new DVCSRequest based on the state of this builder. </returns>
		/// <exception cref="DVCSException"> if an issue occurs during construction. </exception>
		public virtual DVCSRequest build(MessageImprint messageImprint)
		{
			Data data = new Data(messageImprint.toASN1Structure());

			return createDVCRequest(data);
		}
	}

}
using System;

namespace org.bouncycastle.dvcs
{

	using DVCSRequestInformationBuilder = org.bouncycastle.asn1.dvcs.DVCSRequestInformationBuilder;
	using DVCSTime = org.bouncycastle.asn1.dvcs.DVCSTime;
	using Data = org.bouncycastle.asn1.dvcs.Data;
	using ServiceType = org.bouncycastle.asn1.dvcs.ServiceType;
	using CMSSignedData = org.bouncycastle.cms.CMSSignedData;

	/// <summary>
	/// Builder of DVCS requests to VSD service (Verify Signed Document).
	/// </summary>
	public class VSDRequestBuilder : DVCSRequestBuilder
	{
		public VSDRequestBuilder() : base(new DVCSRequestInformationBuilder(ServiceType.VSD))
		{
		}

		public virtual void setRequestTime(DateTime requestTime)
		{
			requestInformationBuilder.setRequestTime(new DVCSTime(requestTime));
		}

		/// <summary>
		/// Build VSD request from CMS SignedData object.
		/// </summary>
		/// <param name="document"> the CMS SignedData to include in the request. </param>
		/// <returns> a new DVCSRequest based on the state of this builder. </returns>
		/// <exception cref="DVCSException"> if an issue occurs during construction. </exception>
		public virtual DVCSRequest build(CMSSignedData document)
		{
			try
			{
				Data data = new Data(document.getEncoded());

				return createDVCRequest(data);
			}
			catch (IOException e)
			{
				throw new DVCSException("Failed to encode CMS signed data", e);
			}
		}
	}

}
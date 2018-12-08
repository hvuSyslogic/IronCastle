using org.bouncycastle.asn1.dvcs;

using System;

namespace org.bouncycastle.dvcs
{
	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using SignedData = org.bouncycastle.asn1.cms.SignedData;
	using DVCSObjectIdentifiers = org.bouncycastle.asn1.dvcs.DVCSObjectIdentifiers;
	using ServiceType = org.bouncycastle.asn1.dvcs.ServiceType;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using CMSSignedData = org.bouncycastle.cms.CMSSignedData;

	/// <summary>
	/// DVCRequest is general request to DVCS (RFC 3029).
	/// It represents requests for all types of services.
	/// Requests for different services differ in DVCData structure.
	/// </summary>
	public class DVCSRequest : DVCSMessage
	{
		private DVCSRequest asn1;
		private DVCSRequestInfo reqInfo;
		private DVCSRequestData data;

		/// <summary>
		/// Constructs DVCRequest from CMS SignedData object.
		/// </summary>
		/// <param name="signedData"> the CMS SignedData object containing the request </param>
		/// <exception cref="DVCSConstructionException"> </exception>
		public DVCSRequest(CMSSignedData signedData) : this(SignedData.getInstance(signedData.toASN1Structure().getContent()).getEncapContentInfo())
		{
		}

		/// <summary>
		/// Construct a DVCS Request from a ContentInfo
		/// </summary>
		/// <param name="contentInfo"> the contentInfo representing the DVCSRequest </param>
		/// <exception cref="DVCSConstructionException"> </exception>
		public DVCSRequest(ContentInfo contentInfo) : base(contentInfo)
		{

			if (!DVCSObjectIdentifiers_Fields.id_ct_DVCSRequestData.Equals(contentInfo.getContentType()))
			{
				throw new DVCSConstructionException("ContentInfo not a DVCS Request");
			}

			try
			{
				if (contentInfo.getContent().toASN1Primitive() is ASN1Sequence)
				{
					this.asn1 = DVCSRequest.getInstance(contentInfo.getContent());
				}
				else
				{
					this.asn1 = DVCSRequest.getInstance(ASN1OctetString.getInstance(contentInfo.getContent()).getOctets());
				}
			}
			catch (Exception e)
			{
				throw new DVCSConstructionException("Unable to parse content: " + e.Message, e);
			}

			this.reqInfo = new DVCSRequestInfo(asn1.getRequestInformation());

			int service = reqInfo.getServiceType();
			if (service == ServiceType.CPD.getValue().intValue())
			{
				this.data = new CPDRequestData(asn1.getData());
			}
			else if (service == ServiceType.VSD.getValue().intValue())
			{
				this.data = new VSDRequestData(asn1.getData());
			}
			else if (service == ServiceType.VPKC.getValue().intValue())
			{
				this.data = new VPKCRequestData(asn1.getData());
			}
			else if (service == ServiceType.CCPD.getValue().intValue())
			{
				this.data = new CCPDRequestData(asn1.getData());
			}
			else
			{
				throw new DVCSConstructionException("Unknown service type: " + service);
			}
		}

		/// <summary>
		/// Return the ASN.1 DVCSRequest structure making up the body of this request.
		/// </summary>
		/// <returns> an org.bouncycastle.asn1.dvcs.DVCSRequest object. </returns>
		public override ASN1Encodable getContent()
		{
			return asn1;
		}

		/// <summary>
		/// Get RequestInformation envelope.
		/// </summary>
		/// <returns> the request info object. </returns>
		public virtual DVCSRequestInfo getRequestInfo()
		{
			return reqInfo;
		}

		/// <summary>
		/// Get data of DVCRequest.
		/// Depending on type of the request it could be different subclasses of DVCRequestData.
		/// </summary>
		/// <returns> the request Data object. </returns>
		public virtual DVCSRequestData getData()
		{
			return data;
		}

		/// <summary>
		/// Get the transaction identifier of request.
		/// </summary>
		/// <returns> the GeneralName representing the Transaction Identifier. </returns>
		public virtual GeneralName getTransactionIdentifier()
		{
			return asn1.getTransactionIdentifier();
		}
	}

}
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
	using CMSSignedData = org.bouncycastle.cms.CMSSignedData;

	/// <summary>
	/// DVCResponse is general response to DVCS (RFC 3029).
	/// It represents responses for all types of services.
	/// </summary>
	public class DVCSResponse : DVCSMessage
	{
		private DVCSResponse asn1;

		/// <summary>
		/// Constructs DVCResponse from CMS SignedData object.
		/// </summary>
		/// <param name="signedData"> the CMS SignedData object containing the request </param>
		/// <exception cref="org.bouncycastle.dvcs.DVCSConstructionException"> </exception>
		public DVCSResponse(CMSSignedData signedData) : this(SignedData.getInstance(signedData.toASN1Structure().getContent()).getEncapContentInfo())
		{
		}

		/// <summary>
		/// Construct a DVCS Response from a ContentInfo
		/// </summary>
		/// <param name="contentInfo"> the contentInfo representing the DVCSRequest </param>
		/// <exception cref="org.bouncycastle.dvcs.DVCSConstructionException"> </exception>
		public DVCSResponse(ContentInfo contentInfo) : base(contentInfo)
		{

			if (!DVCSObjectIdentifiers_Fields.id_ct_DVCSResponseData.Equals(contentInfo.getContentType()))
			{
				throw new DVCSConstructionException("ContentInfo not a DVCS Response");
			}

			try
			{
				if (contentInfo.getContent().toASN1Primitive() is ASN1Sequence)
				{
					this.asn1 = DVCSResponse.getInstance(contentInfo.getContent());
				}
				else
				{
					this.asn1 = DVCSResponse.getInstance(ASN1OctetString.getInstance(contentInfo.getContent()).getOctets());
				}
			}
			catch (Exception e)
			{
				throw new DVCSConstructionException("Unable to parse content: " + e.Message, e);
			}
		}

		/// <summary>
		/// Return the ASN.1 DVCSResponse structure making up the body of this response.
		/// </summary>
		/// <returns> an org.bouncycastle.asn1.dvcs.DVCSResponse object. </returns>
		public override ASN1Encodable getContent()
		{
			return asn1;
		}
	}

}
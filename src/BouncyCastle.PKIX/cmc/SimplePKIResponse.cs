using System;

namespace org.bouncycastle.cmc
{

	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using X509CRLHolder = org.bouncycastle.cert.X509CRLHolder;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using CMSException = org.bouncycastle.cms.CMSException;
	using CMSSignedData = org.bouncycastle.cms.CMSSignedData;
	using Encodable = org.bouncycastle.util.Encodable;
	using Store = org.bouncycastle.util.Store;

	/// <summary>
	/// Carrier for a Simple PKI Response.
	/// <para>
	/// A Simple PKI Response is defined in RFC 5272 as a CMS SignedData object with no EncapsulatedContentInfo
	/// and no SignerInfos attached.
	/// </para>
	/// </summary>
	public class SimplePKIResponse : Encodable
	{
		private readonly CMSSignedData certificateResponse;

		private static ContentInfo parseBytes(byte[] responseEncoding)
		{
			try
			{
				return ContentInfo.getInstance(ASN1Primitive.fromByteArray(responseEncoding));
			}
			catch (Exception e)
			{
				throw new CMCException("malformed data: " + e.Message, e);
			}
		}

		/// <summary>
		/// Create a SimplePKIResponse from the passed in bytes.
		/// </summary>
		/// <param name="responseEncoding"> BER/DER encoding of the certificate. </param>
		/// <exception cref="CMCException"> in the event of corrupted data, or an incorrect structure. </exception>
		public SimplePKIResponse(byte[] responseEncoding) : this(parseBytes(responseEncoding))
		{
		}

		/// <summary>
		/// Create a SimplePKIResponse from the passed in ASN.1 structure.
		/// </summary>
		/// <param name="signedData"> a ContentInfo containing a SignedData. </param>
		public SimplePKIResponse(ContentInfo signedData)
		{
			try
			{
				this.certificateResponse = new CMSSignedData(signedData);
			}
			catch (CMSException e)
			{
				throw new CMCException("malformed response: " + e.Message, e);
			}

			if (certificateResponse.getSignerInfos().size() != 0)
			{
				throw new CMCException("malformed response: SignerInfo structures found");
			}
			if (certificateResponse.getSignedContent() != null)
			{
				throw new CMCException("malformed response: Signed Content found");
			}
		}

		/// <summary>
		/// Return any X.509 certificate objects in this SimplePKIResponse structure as a Store of X509CertificateHolder objects.
		/// </summary>
		/// <returns> a Store of X509CertificateHolder objects. </returns>
		public virtual Store<X509CertificateHolder> getCertificates()
		{
			return certificateResponse.getCertificates();
		}

		/// <summary>
		/// Return any X.509 CRL objects in this SimplePKIResponse structure as a Store of X509CRLHolder objects.
		/// </summary>
		/// <returns> a Store of X509CRLHolder objects. </returns>
		public virtual Store<X509CRLHolder> getCRLs()
		{
			return certificateResponse.getCRLs();
		}

		/// <summary>
		/// return the ASN.1 encoded representation of this object.
		/// </summary>
		public virtual byte[] getEncoded()
		{
			return certificateResponse.getEncoded();
		}
	}

}
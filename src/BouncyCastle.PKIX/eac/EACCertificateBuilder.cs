using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.eac
{

	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using DERApplicationSpecific = org.bouncycastle.asn1.DERApplicationSpecific;
	using CVCertificate = org.bouncycastle.asn1.eac.CVCertificate;
	using CertificateBody = org.bouncycastle.asn1.eac.CertificateBody;
	using CertificateHolderAuthorization = org.bouncycastle.asn1.eac.CertificateHolderAuthorization;
	using CertificateHolderReference = org.bouncycastle.asn1.eac.CertificateHolderReference;
	using CertificationAuthorityReference = org.bouncycastle.asn1.eac.CertificationAuthorityReference;
	using EACTags = org.bouncycastle.asn1.eac.EACTags;
	using PackedDate = org.bouncycastle.asn1.eac.PackedDate;
	using PublicKeyDataObject = org.bouncycastle.asn1.eac.PublicKeyDataObject;
	using EACSigner = org.bouncycastle.eac.@operator.EACSigner;

	public class EACCertificateBuilder
	{
		private static readonly byte[] ZeroArray = new byte [] {0};

		private PublicKeyDataObject publicKey;
		private CertificateHolderAuthorization certificateHolderAuthorization;
		private PackedDate certificateEffectiveDate;
		private PackedDate certificateExpirationDate;
		private CertificateHolderReference certificateHolderReference;
		private CertificationAuthorityReference certificationAuthorityReference;

		public EACCertificateBuilder(CertificationAuthorityReference certificationAuthorityReference, PublicKeyDataObject publicKey, CertificateHolderReference certificateHolderReference, CertificateHolderAuthorization certificateHolderAuthorization, PackedDate certificateEffectiveDate, PackedDate certificateExpirationDate)
		{
			this.certificationAuthorityReference = certificationAuthorityReference;
			this.publicKey = publicKey;
			this.certificateHolderReference = certificateHolderReference;
			this.certificateHolderAuthorization = certificateHolderAuthorization;
			this.certificateEffectiveDate = certificateEffectiveDate;
			this.certificateExpirationDate = certificateExpirationDate;
		}

		private CertificateBody buildBody()
		{
			DERApplicationSpecific certificateProfileIdentifier;

			certificateProfileIdentifier = new DERApplicationSpecific(EACTags.INTERCHANGE_PROFILE, ZeroArray);

			CertificateBody body = new CertificateBody(certificateProfileIdentifier, certificationAuthorityReference, publicKey, certificateHolderReference, certificateHolderAuthorization, certificateEffectiveDate, certificateExpirationDate);

			return body;
		}

		public virtual EACCertificateHolder build(EACSigner signer)
		{
			try
			{
				CertificateBody body = buildBody();

				OutputStream vOut = signer.getOutputStream();

				vOut.write(body.getEncoded(ASN1Encoding_Fields.DER));

				vOut.close();

				return new EACCertificateHolder(new CVCertificate(body, signer.getSignature()));
			}
			catch (Exception e)
			{
				throw new EACException("unable to process signature: " + e.Message, e);
			}
		}
	}

}
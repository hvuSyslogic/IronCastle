using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.eac
{

	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1ParsingException = org.bouncycastle.asn1.ASN1ParsingException;
	using CVCertificate = org.bouncycastle.asn1.eac.CVCertificate;
	using PublicKeyDataObject = org.bouncycastle.asn1.eac.PublicKeyDataObject;
	using EACSignatureVerifier = org.bouncycastle.eac.@operator.EACSignatureVerifier;

	public class EACCertificateHolder
	{
		private CVCertificate cvCertificate;

		private static CVCertificate parseBytes(byte[] certEncoding)
		{
			try
			{
				return CVCertificate.getInstance(certEncoding);
			}
			catch (ClassCastException e)
			{
				throw new EACIOException("malformed data: " + e.getMessage(), e);
			}
			catch (IllegalArgumentException e)
			{
				throw new EACIOException("malformed data: " + e.getMessage(), e);
			}
			catch (ASN1ParsingException e)
			{
				if (e.getCause() is IOException)
				{
					throw (IOException)e.getCause();
				}
				else
				{
					throw new EACIOException("malformed data: " + e.getMessage(), e);
				}
			}
		}

		public EACCertificateHolder(byte[] certEncoding) : this(parseBytes(certEncoding))
		{
		}

		public EACCertificateHolder(CVCertificate cvCertificate)
		{
			this.cvCertificate = cvCertificate;
		}

		/// <summary>
		/// Return the underlying ASN.1 structure for the certificate in this holder.
		/// </summary>
		/// <returns> a X509CertificateStructure object. </returns>
		public virtual CVCertificate toASN1Structure()
		{
			return cvCertificate;
		}

		public virtual PublicKeyDataObject getPublicKeyDataObject()
		{
			return cvCertificate.getBody().getPublicKey();
		}

		public virtual bool isSignatureValid(EACSignatureVerifier verifier)
		{
			try
			{
				OutputStream vOut = verifier.getOutputStream();

				vOut.write(cvCertificate.getBody().getEncoded(ASN1Encoding_Fields.DER));

				vOut.close();

				return verifier.verify(cvCertificate.getSignature());
			}
			catch (Exception e)
			{
				throw new EACException("unable to process signature: " + e.Message, e);
			}
		}
	}

}
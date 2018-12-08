using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.eac
{

	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1ParsingException = org.bouncycastle.asn1.ASN1ParsingException;
	using CVCertificateRequest = org.bouncycastle.asn1.eac.CVCertificateRequest;
	using PublicKeyDataObject = org.bouncycastle.asn1.eac.PublicKeyDataObject;
	using EACSignatureVerifier = org.bouncycastle.eac.@operator.EACSignatureVerifier;

	public class EACCertificateRequestHolder
	{
		private CVCertificateRequest request;

		private static CVCertificateRequest parseBytes(byte[] requestEncoding)
		{
			try
			{
				return CVCertificateRequest.getInstance(requestEncoding);
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

		public EACCertificateRequestHolder(byte[] certEncoding) : this(parseBytes(certEncoding))
		{
		}

		public EACCertificateRequestHolder(CVCertificateRequest request)
		{
			this.request = request;
		}

		/// <summary>
		/// Return the underlying ASN.1 structure for the certificate in this holder.
		/// </summary>
		/// <returns> a X509CertificateStructure object. </returns>
		public virtual CVCertificateRequest toASN1Structure()
		{
			return request;
		}

		public virtual PublicKeyDataObject getPublicKeyDataObject()
		{
			return request.getPublicKey();
		}

		public virtual bool isInnerSignatureValid(EACSignatureVerifier verifier)
		{
			try
			{
				OutputStream vOut = verifier.getOutputStream();

				vOut.write(request.getCertificateBody().getEncoded(ASN1Encoding_Fields.DER));

				vOut.close();

				return verifier.verify(request.getInnerSignature());
			}
			catch (Exception e)
			{
				throw new EACException("unable to process signature: " + e.Message, e);
			}
		}
	}

}
using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.pkcs
{

	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using ASN1Set = org.bouncycastle.asn1.ASN1Set;
	using Attribute = org.bouncycastle.asn1.pkcs.Attribute;
	using CertificationRequest = org.bouncycastle.asn1.pkcs.CertificationRequest;
	using CertificationRequestInfo = org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using ContentVerifier = org.bouncycastle.@operator.ContentVerifier;
	using ContentVerifierProvider = org.bouncycastle.@operator.ContentVerifierProvider;

	/// <summary>
	/// Holding class for a PKCS#10 certification request.
	/// </summary>
	public class PKCS10CertificationRequest
	{
		private static Attribute[] EMPTY_ARRAY = new Attribute[0];

		private CertificationRequest certificationRequest;

		private static CertificationRequest parseBytes(byte[] encoding)
		{
			try
			{
				return CertificationRequest.getInstance(ASN1Primitive.fromByteArray(encoding));
			}
			catch (ClassCastException e)
			{
				throw new PKCSIOException("malformed data: " + e.getMessage(), e);
			}
			catch (IllegalArgumentException e)
			{
				throw new PKCSIOException("malformed data: " + e.getMessage(), e);
			}
		}

		/// <summary>
		/// Create a PKCS10CertificationRequestHolder from an underlying ASN.1 structure.
		/// </summary>
		/// <param name="certificationRequest"> the underlying ASN.1 structure representing a request. </param>
		public PKCS10CertificationRequest(CertificationRequest certificationRequest)
		{
			 this.certificationRequest = certificationRequest;
		}

		/// <summary>
		/// Create a PKCS10CertificationRequestHolder from the passed in bytes.
		/// </summary>
		/// <param name="encoded"> BER/DER encoding of the CertificationRequest structure. </param>
		/// <exception cref="IOException"> in the event of corrupted data, or an incorrect structure. </exception>
		public PKCS10CertificationRequest(byte[] encoded) : this(parseBytes(encoded))
		{
		}

		/// <summary>
		/// Return the underlying ASN.1 structure for this request.
		/// </summary>
		/// <returns> a CertificateRequest object. </returns>
		public virtual CertificationRequest toASN1Structure()
		{
			 return certificationRequest;
		}

		/// <summary>
		/// Return the subject on this request.
		/// </summary>
		/// <returns> the X500Name representing the request's subject. </returns>
		public virtual X500Name getSubject()
		{
			return X500Name.getInstance(certificationRequest.getCertificationRequestInfo().getSubject());
		}

		/// <summary>
		/// Return the details of the signature algorithm used to create this request.
		/// </summary>
		/// <returns> the AlgorithmIdentifier describing the signature algorithm used to create this request. </returns>
		public virtual AlgorithmIdentifier getSignatureAlgorithm()
		{
			return certificationRequest.getSignatureAlgorithm();
		}

		/// <summary>
		/// Return the bytes making up the signature associated with this request.
		/// </summary>
		/// <returns> the request signature bytes. </returns>
		public virtual byte[] getSignature()
		{
			return certificationRequest.getSignature().getOctets();
		}

		/// <summary>
		/// Return the SubjectPublicKeyInfo describing the public key this request is carrying.
		/// </summary>
		/// <returns> the public key ASN.1 structure contained in the request. </returns>
		public virtual SubjectPublicKeyInfo getSubjectPublicKeyInfo()
		{
			return certificationRequest.getCertificationRequestInfo().getSubjectPublicKeyInfo();
		}

		/// <summary>
		/// Return the attributes, if any associated with this request.
		/// </summary>
		/// <returns> an array of Attribute, zero length if none present. </returns>
		public virtual Attribute[] getAttributes()
		{
			ASN1Set attrSet = certificationRequest.getCertificationRequestInfo().getAttributes();

			if (attrSet == null)
			{
				return EMPTY_ARRAY;
			}

			Attribute[] attrs = new Attribute[attrSet.size()];

			for (int i = 0; i != attrSet.size(); i++)
			{
				attrs[i] = Attribute.getInstance(attrSet.getObjectAt(i));
			}

			return attrs;
		}

		/// <summary>
		/// Return an  array of attributes matching the passed in type OID.
		/// </summary>
		/// <param name="type"> the type of the attribute being looked for. </param>
		/// <returns> an array of Attribute of the requested type, zero length if none present. </returns>
		public virtual Attribute[] getAttributes(ASN1ObjectIdentifier type)
		{
			ASN1Set attrSet = certificationRequest.getCertificationRequestInfo().getAttributes();

			if (attrSet == null)
			{
				return EMPTY_ARRAY;
			}

			List list = new ArrayList();

			for (int i = 0; i != attrSet.size(); i++)
			{
				Attribute attr = Attribute.getInstance(attrSet.getObjectAt(i));
				if (attr.getAttrType().Equals(type))
				{
					list.add(attr);
				}
			}

			if (list.size() == 0)
			{
				return EMPTY_ARRAY;
			}

			return (Attribute[])list.toArray(new Attribute[list.size()]);
		}

		public virtual byte[] getEncoded()
		{
			return certificationRequest.getEncoded();
		}

		/// <summary>
		/// Validate the signature on the PKCS10 certification request in this holder.
		/// </summary>
		/// <param name="verifierProvider"> a ContentVerifierProvider that can generate a verifier for the signature. </param>
		/// <returns> true if the signature is valid, false otherwise. </returns>
		/// <exception cref="PKCSException"> if the signature cannot be processed or is inappropriate. </exception>
		public virtual bool isSignatureValid(ContentVerifierProvider verifierProvider)
		{
			CertificationRequestInfo requestInfo = certificationRequest.getCertificationRequestInfo();

			ContentVerifier verifier;

			try
			{
				verifier = verifierProvider.get(certificationRequest.getSignatureAlgorithm());

				OutputStream sOut = verifier.getOutputStream();

				sOut.write(requestInfo.getEncoded(ASN1Encoding_Fields.DER));

				sOut.close();
			}
			catch (Exception e)
			{
				throw new PKCSException("unable to process signature: " + e.Message, e);
			}

			return verifier.verify(this.getSignature());
		}

		public override bool Equals(object o)
		{
			if (o == this)
			{
				return true;
			}

			if (!(o is PKCS10CertificationRequest))
			{
				return false;
			}

			PKCS10CertificationRequest other = (PKCS10CertificationRequest)o;

			return this.toASN1Structure().Equals(other.toASN1Structure());
		}

		public override int GetHashCode()
		{
			return this.toASN1Structure().GetHashCode();
		}
	}

}
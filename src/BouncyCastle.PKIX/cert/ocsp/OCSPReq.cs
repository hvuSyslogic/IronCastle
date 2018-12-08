using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.cert.ocsp
{

	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1Exception = org.bouncycastle.asn1.ASN1Exception;
	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OutputStream = org.bouncycastle.asn1.ASN1OutputStream;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using OCSPRequest = org.bouncycastle.asn1.ocsp.OCSPRequest;
	using Request = org.bouncycastle.asn1.ocsp.Request;
	using Certificate = org.bouncycastle.asn1.x509.Certificate;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using Extensions = org.bouncycastle.asn1.x509.Extensions;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using ContentVerifier = org.bouncycastle.@operator.ContentVerifier;
	using ContentVerifierProvider = org.bouncycastle.@operator.ContentVerifierProvider;

	/// <summary>
	/// <pre>
	/// OCSPRequest     ::=     SEQUENCE {
	///       tbsRequest                  TBSRequest,
	///       optionalSignature   [0]     EXPLICIT Signature OPTIONAL }
	/// 
	///   TBSRequest      ::=     SEQUENCE {
	///       version             [0]     EXPLICIT Version DEFAULT v1,
	///       requestorName       [1]     EXPLICIT GeneralName OPTIONAL,
	///       requestList                 SEQUENCE OF Request,
	///       requestExtensions   [2]     EXPLICIT Extensions OPTIONAL }
	/// 
	///   Signature       ::=     SEQUENCE {
	///       signatureAlgorithm      AlgorithmIdentifier,
	///       signature               BIT STRING,
	///       certs               [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL}
	/// 
	///   Version         ::=             INTEGER  {  v1(0) }
	/// 
	///   Request         ::=     SEQUENCE {
	///       reqCert                     CertID,
	///       singleRequestExtensions     [0] EXPLICIT Extensions OPTIONAL }
	/// 
	///   CertID          ::=     SEQUENCE {
	///       hashAlgorithm       AlgorithmIdentifier,
	///       issuerNameHash      OCTET STRING, -- Hash of Issuer's DN
	///       issuerKeyHash       OCTET STRING, -- Hash of Issuers public key
	///       serialNumber        CertificateSerialNumber }
	/// </pre>
	/// </summary>
	public class OCSPReq
	{
		private static readonly X509CertificateHolder[] EMPTY_CERTS = new X509CertificateHolder[0];

		private OCSPRequest req;
		private Extensions extensions;

		public OCSPReq(OCSPRequest req)
		{
			this.req = req;
			this.extensions = req.getTbsRequest().getRequestExtensions();
		}

		public OCSPReq(byte[] req) : this(new ASN1InputStream(req))
		{
		}

		private OCSPReq(ASN1InputStream aIn)
		{
			try
			{
				this.req = OCSPRequest.getInstance(aIn.readObject());
				if (req == null)
				{
					throw new CertIOException("malformed request: no request data found");
				}
				this.extensions = req.getTbsRequest().getRequestExtensions();
			}
			catch (IllegalArgumentException e)
			{
				throw new CertIOException("malformed request: " + e.getMessage(), e);
			}
			catch (ClassCastException e)
			{
				throw new CertIOException("malformed request: " + e.getMessage(), e);
			}
			catch (ASN1Exception e)
			{
				throw new CertIOException("malformed request: " + e.getMessage(), e);
			}
		}

		public virtual int getVersionNumber()
		{
			return req.getTbsRequest().getVersion().getValue().intValue() + 1;
		}

		public virtual GeneralName getRequestorName()
		{
			return GeneralName.getInstance(req.getTbsRequest().getRequestorName());
		}

		public virtual Req[] getRequestList()
		{
			ASN1Sequence seq = req.getTbsRequest().getRequestList();
			Req[] requests = new Req[seq.size()];

			for (int i = 0; i != requests.Length; i++)
			{
				requests[i] = new Req(Request.getInstance(seq.getObjectAt(i)));
			}

			return requests;
		}

		public virtual bool hasExtensions()
		{
			return extensions != null;
		}

		public virtual Extension getExtension(ASN1ObjectIdentifier oid)
		{
			if (extensions != null)
			{
				return extensions.getExtension(oid);
			}

			return null;
		}

		public virtual List getExtensionOIDs()
		{
			return OCSPUtils.getExtensionOIDs(extensions);
		}

		public virtual Set getCriticalExtensionOIDs()
		{
			return OCSPUtils.getCriticalExtensionOIDs(extensions);
		}

		public virtual Set getNonCriticalExtensionOIDs()
		{
			return OCSPUtils.getNonCriticalExtensionOIDs(extensions);
		}

		/// <summary>
		/// return the object identifier representing the signature algorithm
		/// </summary>
		public virtual ASN1ObjectIdentifier getSignatureAlgOID()
		{
			if (!this.isSigned())
			{
				return null;
			}

			return req.getOptionalSignature().getSignatureAlgorithm().getAlgorithm();
		}

		public virtual byte[] getSignature()
		{
			if (!this.isSigned())
			{
				return null;
			}

			return req.getOptionalSignature().getSignature().getOctets();
		}

		public virtual X509CertificateHolder[] getCerts()
		{
			//
			// load the certificates if we have any
			//
			if (req.getOptionalSignature() != null)
			{
				ASN1Sequence s = req.getOptionalSignature().getCerts();

				if (s != null)
				{
					X509CertificateHolder[] certs = new X509CertificateHolder[s.size()];

					for (int i = 0; i != certs.Length; i++)
					{
						certs[i] = new X509CertificateHolder(Certificate.getInstance(s.getObjectAt(i)));
					}

					return certs;
				}

				return EMPTY_CERTS;
			}
			else
			{
				return EMPTY_CERTS;
			}
		}

		/// <summary>
		/// Return whether or not this request is signed.
		/// </summary>
		/// <returns> true if signed false otherwise. </returns>
		public virtual bool isSigned()
		{
			return req.getOptionalSignature() != null;
		}

		/// <summary>
		/// verify the signature against the TBSRequest object we contain.
		/// </summary>
		public virtual bool isSignatureValid(ContentVerifierProvider verifierProvider)
		{
			if (!this.isSigned())
			{
				throw new OCSPException("attempt to verify signature on unsigned object");
			}

			try
			{
				ContentVerifier verifier = verifierProvider.get(req.getOptionalSignature().getSignatureAlgorithm());
				OutputStream sOut = verifier.getOutputStream();

				sOut.write(req.getTbsRequest().getEncoded(ASN1Encoding_Fields.DER));

				return verifier.verify(this.getSignature());
			}
			catch (Exception e)
			{
				throw new OCSPException("exception processing signature: " + e, e);
			}
		}

		/// <summary>
		/// return the ASN.1 encoded representation of this object.
		/// </summary>
		public virtual byte[] getEncoded()
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			ASN1OutputStream aOut = new ASN1OutputStream(bOut);

			aOut.writeObject(req);

			return bOut.toByteArray();
		}
	}

}
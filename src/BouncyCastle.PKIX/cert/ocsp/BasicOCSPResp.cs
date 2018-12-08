using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.cert.ocsp
{

	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using BasicOCSPResponse = org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
	using ResponseData = org.bouncycastle.asn1.ocsp.ResponseData;
	using SingleResponse = org.bouncycastle.asn1.ocsp.SingleResponse;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using Certificate = org.bouncycastle.asn1.x509.Certificate;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using Extensions = org.bouncycastle.asn1.x509.Extensions;
	using ContentVerifier = org.bouncycastle.@operator.ContentVerifier;
	using ContentVerifierProvider = org.bouncycastle.@operator.ContentVerifierProvider;
	using Encodable = org.bouncycastle.util.Encodable;

	/// <summary>
	/// <pre>
	/// BasicOCSPResponse       ::= SEQUENCE {
	///    tbsResponseData      ResponseData,
	///    signatureAlgorithm   AlgorithmIdentifier,
	///    signature            BIT STRING,
	///    certs                [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
	/// </pre>
	/// </summary>
	public class BasicOCSPResp : Encodable
	{
		private BasicOCSPResponse resp;
		private ResponseData data;
		private Extensions extensions;

		public BasicOCSPResp(BasicOCSPResponse resp)
		{
			this.resp = resp;
			this.data = resp.getTbsResponseData();
			this.extensions = Extensions.getInstance(resp.getTbsResponseData().getResponseExtensions());
		}

		/// <summary>
		/// Return the DER encoding of the tbsResponseData field. </summary>
		/// <returns> DER encoding of tbsResponseData </returns>
		public virtual byte[] getTBSResponseData()
		{
			try
			{
				return resp.getTbsResponseData().getEncoded(ASN1Encoding_Fields.DER);
			}
			catch (IOException)
			{
				return null;
			}
		}

		/// <summary>
		/// Return the algorithm identifier describing the signature used in the response.
		/// </summary>
		/// <returns> an AlgorithmIdentifier </returns>
		public virtual AlgorithmIdentifier getSignatureAlgorithmID()
		{
			return resp.getSignatureAlgorithm();
		}

		public virtual int getVersion()
		{
			return data.getVersion().getValue().intValue() + 1;
		}

		public virtual RespID getResponderId()
		{
			return new RespID(data.getResponderID());
		}

		public virtual DateTime getProducedAt()
		{
			return OCSPUtils.extractDate(data.getProducedAt());
		}

		public virtual SingleResp[] getResponses()
		{
			ASN1Sequence s = data.getResponses();
			SingleResp[] rs = new SingleResp[s.size()];

			for (int i = 0; i != rs.Length; i++)
			{
				rs[i] = new SingleResp(SingleResponse.getInstance(s.getObjectAt(i)));
			}

			return rs;
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


		public virtual ASN1ObjectIdentifier getSignatureAlgOID()
		{
			return resp.getSignatureAlgorithm().getAlgorithm();
		}

		public virtual byte[] getSignature()
		{
			return resp.getSignature().getOctets();
		}

		public virtual X509CertificateHolder[] getCerts()
		{
			//
			// load the certificates if we have any
			//
			if (resp.getCerts() != null)
			{
				ASN1Sequence s = resp.getCerts();

				if (s != null)
				{
					X509CertificateHolder[] certs = new X509CertificateHolder[s.size()];

					for (int i = 0; i != certs.Length; i++)
					{
						certs[i] = new X509CertificateHolder(Certificate.getInstance(s.getObjectAt(i)));
					}

					return certs;
				}

				return OCSPUtils.EMPTY_CERTS;
			}
			else
			{
				return OCSPUtils.EMPTY_CERTS;
			}
		}

		/// <summary>
		/// verify the signature against the tbsResponseData object we contain.
		/// </summary>
		public virtual bool isSignatureValid(ContentVerifierProvider verifierProvider)
		{
			try
			{
				ContentVerifier verifier = verifierProvider.get(resp.getSignatureAlgorithm());
				OutputStream vOut = verifier.getOutputStream();

				vOut.write(resp.getTbsResponseData().getEncoded(ASN1Encoding_Fields.DER));
				vOut.close();

				return verifier.verify(this.getSignature());
			}
			catch (Exception e)
			{
				throw new OCSPException("exception processing sig: " + e, e);
			}
		}

		/// <summary>
		/// return the ASN.1 encoded representation of this object.
		/// </summary>
		public virtual byte[] getEncoded()
		{
			return resp.getEncoded();
		}

		public override bool Equals(object o)
		{
			if (o == this)
			{
				return true;
			}

			if (!(o is BasicOCSPResp))
			{
				return false;
			}

			BasicOCSPResp r = (BasicOCSPResp)o;

			return resp.Equals(r.resp);
		}

		public override int GetHashCode()
		{
			return resp.GetHashCode();
		}
	}

}
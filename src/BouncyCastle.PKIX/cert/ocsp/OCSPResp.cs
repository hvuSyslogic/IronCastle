using org.bouncycastle.asn1.ocsp;

using System;

namespace org.bouncycastle.cert.ocsp
{

	using ASN1Exception = org.bouncycastle.asn1.ASN1Exception;
	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using BasicOCSPResponse = org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
	using OCSPObjectIdentifiers = org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
	using OCSPResponse = org.bouncycastle.asn1.ocsp.OCSPResponse;
	using ResponseBytes = org.bouncycastle.asn1.ocsp.ResponseBytes;

	public class OCSPResp
	{
		public const int SUCCESSFUL = 0; // Response has valid confirmations
		public const int MALFORMED_REQUEST = 1; // Illegal confirmation request
		public const int INTERNAL_ERROR = 2; // Internal error in issuer
		public const int TRY_LATER = 3; // Try again later
		// (4) is not used
		public const int SIG_REQUIRED = 5; // Must sign the request
		public const int UNAUTHORIZED = 6; // Request unauthorized

		private OCSPResponse resp;

		public OCSPResp(OCSPResponse resp)
		{
			this.resp = resp;
		}

		public OCSPResp(byte[] resp) : this(new ByteArrayInputStream(resp))
		{
		}

		public OCSPResp(InputStream resp) : this(new ASN1InputStream(resp))
		{
		}

		private OCSPResp(ASN1InputStream aIn)
		{
			try
			{
				this.resp = OCSPResponse.getInstance(aIn.readObject());
			}
			catch (IllegalArgumentException e)
			{
				throw new CertIOException("malformed response: " + e.getMessage(), e);
			}
			catch (ClassCastException e)
			{
				throw new CertIOException("malformed response: " + e.getMessage(), e);
			}
			catch (ASN1Exception e)
			{
				throw new CertIOException("malformed response: " + e.getMessage(), e);
			}

			if (resp == null)
			{
				throw new CertIOException("malformed response: no response data found");
			}
		}

		public virtual int getStatus()
		{
			return this.resp.getResponseStatus().getValue().intValue();
		}

		public virtual object getResponseObject()
		{
			ResponseBytes rb = this.resp.getResponseBytes();

			if (rb == null)
			{
				return null;
			}

			if (rb.getResponseType().Equals(OCSPObjectIdentifiers_Fields.id_pkix_ocsp_basic))
			{
				try
				{
					ASN1Primitive obj = ASN1Primitive.fromByteArray(rb.getResponse().getOctets());
					return new BasicOCSPResp(BasicOCSPResponse.getInstance(obj));
				}
				catch (Exception e)
				{
					throw new OCSPException("problem decoding object: " + e, e);
				}
			}

			return rb.getResponse();
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

			if (!(o is OCSPResp))
			{
				return false;
			}

			OCSPResp r = (OCSPResp)o;

			return resp.Equals(r.resp);
		}

		public override int GetHashCode()
		{
			return resp.GetHashCode();
		}

		public virtual OCSPResponse toASN1Structure()
		{
			return resp;
		}
	}

}
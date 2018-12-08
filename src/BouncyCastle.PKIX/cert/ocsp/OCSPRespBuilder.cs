using org.bouncycastle.asn1.ocsp;

namespace org.bouncycastle.cert.ocsp
{

	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using OCSPObjectIdentifiers = org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
	using OCSPResponse = org.bouncycastle.asn1.ocsp.OCSPResponse;
	using OCSPResponseStatus = org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
	using ResponseBytes = org.bouncycastle.asn1.ocsp.ResponseBytes;

	/// <summary>
	/// base generator for an OCSP response - at the moment this only supports the
	/// generation of responses containing BasicOCSP responses.
	/// </summary>
	public class OCSPRespBuilder
	{
		public const int SUCCESSFUL = 0; // Response has valid confirmations
		public const int MALFORMED_REQUEST = 1; // Illegal confirmation request
		public const int INTERNAL_ERROR = 2; // Internal error in issuer
		public const int TRY_LATER = 3; // Try again later
		// (4) is not used
		public const int SIG_REQUIRED = 5; // Must sign the request
		public const int UNAUTHORIZED = 6; // Request unauthorized

		public virtual OCSPResp build(int status, object response)
		{
			if (response == null)
			{
				return new OCSPResp(new OCSPResponse(new OCSPResponseStatus(status), null));
			}

			if (response is BasicOCSPResp)
			{
				BasicOCSPResp r = (BasicOCSPResp)response;
				ASN1OctetString octs;

				try
				{
					octs = new DEROctetString(r.getEncoded());
				}
				catch (IOException e)
				{
					throw new OCSPException("can't encode object.", e);
				}

				ResponseBytes rb = new ResponseBytes(OCSPObjectIdentifiers_Fields.id_pkix_ocsp_basic, octs);

				return new OCSPResp(new OCSPResponse(new OCSPResponseStatus(status), rb));
			}

			throw new OCSPException("unknown response object");
		}
	}

}
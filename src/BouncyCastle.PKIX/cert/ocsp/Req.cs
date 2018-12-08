namespace org.bouncycastle.cert.ocsp
{
	using Request = org.bouncycastle.asn1.ocsp.Request;
	using Extensions = org.bouncycastle.asn1.x509.Extensions;

	public class Req
	{
		private Request req;

		public Req(Request req)
		{
			this.req = req;
		}

		public virtual CertificateID getCertID()
		{
			return new CertificateID(req.getReqCert());
		}

		public virtual Extensions getSingleRequestExtensions()
		{
			return req.getSingleRequestExtensions();
		}
	}

}
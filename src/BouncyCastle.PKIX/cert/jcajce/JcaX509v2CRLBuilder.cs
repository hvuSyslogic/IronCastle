using System;

namespace org.bouncycastle.cert.jcajce
{

	using X500Name = org.bouncycastle.asn1.x500.X500Name;

	public class JcaX509v2CRLBuilder : X509v2CRLBuilder
	{
		public JcaX509v2CRLBuilder(X500Principal issuer, DateTime now) : base(X500Name.getInstance(issuer.getEncoded()), now)
		{
		}

		public JcaX509v2CRLBuilder(X509Certificate issuerCert, DateTime now) : this(issuerCert.getSubjectX500Principal(), now)
		{
		}
	}

}
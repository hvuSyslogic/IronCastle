namespace org.bouncycastle.est.test
{


	using TestCase = junit.framework.TestCase;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using JcaX509CertificateConverter = org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
	using JsseDefaultHostnameAuthorizer = org.bouncycastle.est.jcajce.JsseDefaultHostnameAuthorizer;
	using PemReader = org.bouncycastle.util.io.pem.PemReader;

	/// <summary>
	/// TestHostNameAuthorizer tests the hostname authorizer only. EST related functions
	/// are not tested here.
	/// </summary>
	public class TestHostNameAuthorizer : TestCase
	{
		private static X509Certificate readPemCertificate(string path)
		{
			InputStreamReader fr = new InputStreamReader(typeof(TestHostNameAuthorizer).getResourceAsStream(path));
			PemReader reader = new PemReader(fr);
			X509CertificateHolder fromFile = new X509CertificateHolder(reader.readPemObject().getContent());
			reader.close();
			fr.close();
			return (new JcaX509CertificateConverter()).setProvider("BC").getCertificate(fromFile);
		}

		/*
		    The following tests do not attempt to validate the certificates.
		    They only test hostname verification behavior.
		 */
		public virtual void testCNMatch()
		{
			X509Certificate cert = readPemCertificate("san/cert_cn_match_wc.pem");

			assertTrue("Common Name match", (new JsseDefaultHostnameAuthorizer(null)).verify("aardvark.cisco.com", cert));
			assertFalse("Not match", (new JsseDefaultHostnameAuthorizer(null)).verify("cisco.com", cert));
		}

		public virtual void testCNMismatch_1()
		{
			X509Certificate cert = readPemCertificate("san/cert_cn_mismatch_wc.pem");

			assertFalse("Not match", (new JsseDefaultHostnameAuthorizer(null)).verify("aardvark", cert));
		}


		// 192.168.1.50
		public virtual void testCNIPMismatch()
		{
			X509Certificate cert = readPemCertificate("san/cert_cn_mismatch_ip.pem");

			assertFalse("Not match", (new JsseDefaultHostnameAuthorizer(null)).verify("127.0.0.1", cert));
		}

		public virtual void testWCMismatch()
		{
			X509Certificate cert = readPemCertificate("san/cert_cn_mismatch_ip.pem");

			assertFalse("Not match", (new JsseDefaultHostnameAuthorizer(null)).verify("aardvark.cisco.com", cert));
		}

		public virtual void testSANMatch()
		{
			X509Certificate cert = readPemCertificate("san/cert_san_match.pem");
			assertTrue("Match", (new JsseDefaultHostnameAuthorizer(null)).verify("localhost.cisco.com", cert));
		}

		public virtual void testSANMatchIP()
		{
			X509Certificate cert = readPemCertificate("san/cert_san_match_ip.pem");
			assertTrue("Match", (new JsseDefaultHostnameAuthorizer(null)).verify("192.168.51.140", cert));
			assertTrue("Match", (new JsseDefaultHostnameAuthorizer(null)).verify("127.0.0.1", cert));
			assertFalse("Not Match", (new JsseDefaultHostnameAuthorizer(null)).verify("10.0.0.1", cert));
		}

		public virtual void testSANMatchWC()
		{
			X509Certificate cert = readPemCertificate("san/cert_san_mismatch_wc.pem");
			assertTrue("Match", (new JsseDefaultHostnameAuthorizer(null)).verify("roundhouse.yahoo.com", cert));
			assertFalse("Not Match", (new JsseDefaultHostnameAuthorizer(null)).verify("aardvark.cisco.com", cert));
		}

		public virtual void testSANMismatchIP()
		{
			X509Certificate cert = readPemCertificate("san/cert_san_mismatch_ip.pem");
			assertFalse("Not Match", (new JsseDefaultHostnameAuthorizer(null)).verify("localhost.me", cert));
		}

		public virtual void testSANMismatchWC()
		{
			X509Certificate cert = readPemCertificate("san/cert_san_mismatch_wc.pem");
			assertFalse("Not Match", (new JsseDefaultHostnameAuthorizer(null)).verify("localhost.me", cert));
		}
	}

}
namespace org.bouncycastle.cert.test
{

	using DANEEntry = org.bouncycastle.cert.dane.DANEEntry;
	using DANEEntryFactory = org.bouncycastle.cert.dane.DANEEntryFactory;
	using DANEException = org.bouncycastle.cert.dane.DANEException;
	using TruncatingDigestCalculator = org.bouncycastle.cert.dane.TruncatingDigestCalculator;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using Arrays = org.bouncycastle.util.Arrays;
	using Base64 = org.bouncycastle.util.encoders.Base64;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class DANETest : SimpleTest
	{
		internal byte[] randomCert = Base64.decode("MIIDbDCCAtWgAwIBAgIBADANBgkqhkiG9w0BAQQFADCBtzELMAkGA1UEBhMCQVUx" + "ETAPBgNVBAgTCFZpY3RvcmlhMRgwFgYDVQQHEw9Tb3V0aCBNZWxib3VybmUxGjAY" + "BgNVBAoTEUNvbm5lY3QgNCBQdHkgTHRkMR4wHAYDVQQLExVDZXJ0aWZpY2F0ZSBB" + "dXRob3JpdHkxFTATBgNVBAMTDENvbm5lY3QgNCBDQTEoMCYGCSqGSIb3DQEJARYZ" + "d2VibWFzdGVyQGNvbm5lY3Q0LmNvbS5hdTAeFw0wMDA2MDIwNzU1MzNaFw0wMTA2" + "MDIwNzU1MzNaMIG3MQswCQYDVQQGEwJBVTERMA8GA1UECBMIVmljdG9yaWExGDAW" + "BgNVBAcTD1NvdXRoIE1lbGJvdXJuZTEaMBgGA1UEChMRQ29ubmVjdCA0IFB0eSBM" + "dGQxHjAcBgNVBAsTFUNlcnRpZmljYXRlIEF1dGhvcml0eTEVMBMGA1UEAxMMQ29u" + "bmVjdCA0IENBMSgwJgYJKoZIhvcNAQkBFhl3ZWJtYXN0ZXJAY29ubmVjdDQuY29t" + "LmF1MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDgs5ptNG6Qv1ZpCDuUNGmv" + "rhjqMDPd3ri8JzZNRiiFlBA4e6/ReaO1U8ASewDeQMH6i9R6degFdQRLngbuJP0s" + "xcEE+SksEWNvygfzLwV9J/q+TQDyJYK52utb++lS0b48A1KPLwEsyL6kOAgelbur" + "ukwxowprKUIV7Knf1ajetQIDAQABo4GFMIGCMCQGA1UdEQQdMBuBGXdlYm1hc3Rl" + "ckBjb25uZWN0NC5jb20uYXUwDwYDVR0TBAgwBgEB/wIBADA2BglghkgBhvhCAQ0E" + "KRYnbW9kX3NzbCBnZW5lcmF0ZWQgY3VzdG9tIENBIGNlcnRpZmljYXRlMBEGCWCG" + "SAGG+EIBAQQEAwICBDANBgkqhkiG9w0BAQQFAAOBgQCsGvfdghH8pPhlwm1r3pQk" + "msnLAVIBb01EhbXm2861iXZfWqGQjrGAaA0ZpXNk9oo110yxoqEoSJSzniZa7Xtz" + "soTwNUpE0SLHvWf/SlKdFWlzXA+vOZbzEv4UmjeelekTm7lc01EEa5QRVzOxHFtQ" + "DhkaJ8VqOMajkQFma2r9iA==");

		public override string getName()
		{
			return "DANETest";
		}

		private void shouldCreateDANEEntry()
		{
			DANEEntryFactory daneEntryFactory = new DANEEntryFactory(new TruncatingDigestCalculator(new SHA256DigestCalculator()));

			DANEEntry entry = daneEntryFactory.createEntry("test@test.com", new X509CertificateHolder(randomCert));

			if (!DANEEntry.isValidCertificate(entry.getRDATA()))
			{
				fail("encoding error in RDATA");
			}

			if (!"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15._smimecert.test.com".Equals(entry.getDomainName()))
			{
				fail("domain name associated with entry wrong");
			}

			byte[] rdata = entry.getRDATA();
			byte[] certData = new byte[rdata.Length - 3];

			JavaSystem.arraycopy(rdata, 3, certData, 0, certData.Length);

			if (!Arrays.areEqual(certData, randomCert))
			{
				fail("certificate encoding does not match");
			}
		}

		public override void performTest()
		{
			 shouldCreateDANEEntry();
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new DANETest());
		}
	}

}
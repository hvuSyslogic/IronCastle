namespace org.bouncycastle.cert.test
{

	using Test = junit.framework.Test;
	using TestCase = junit.framework.TestCase;
	using TestSuite = junit.framework.TestSuite;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using X509CertificateHolderSelector = org.bouncycastle.cert.selector.X509CertificateHolderSelector;
	using JcaSelectorConverter = org.bouncycastle.cert.selector.jcajce.JcaSelectorConverter;
	using JcaX509CertSelectorConverter = org.bouncycastle.cert.selector.jcajce.JcaX509CertSelectorConverter;
	using Arrays = org.bouncycastle.util.Arrays;

	public class ConverterTest : TestCase
	{
		public virtual void testCertificateSelectorConversion()
		{
			JcaX509CertSelectorConverter converter = new JcaX509CertSelectorConverter();
			JcaSelectorConverter toSelector = new JcaSelectorConverter();

			X509CertificateHolderSelector sid1 = new X509CertificateHolderSelector(new X500Name("CN=Test"), BigInteger.valueOf(1), new byte[20]);

			X509CertSelector conv = converter.getCertSelector(sid1);

			assertTrue(conv.getIssuerAsString().Equals("CN=Test"));
			assertTrue(Arrays.areEqual(conv.getSubjectKeyIdentifier(), (new DEROctetString(new byte[20])).getEncoded()));
			assertEquals(conv.getSerialNumber(), sid1.getSerialNumber());

			X509CertificateHolderSelector sid2 = toSelector.getCertificateHolderSelector(conv);

			assertEquals(sid1, sid2);

			sid1 = new X509CertificateHolderSelector(new X500Name("CN=Test"), BigInteger.valueOf(1));

			conv = converter.getCertSelector(sid1);

			assertTrue(conv.getIssuerAsString().Equals("CN=Test"));
			assertNull(conv.getSubjectKeyIdentifier());
			assertEquals(conv.getSerialNumber(), sid1.getSerialNumber());

			sid2 = toSelector.getCertificateHolderSelector(conv);

			assertEquals(sid1, sid2);

			sid1 = new X509CertificateHolderSelector(new byte[20]);

			conv = converter.getCertSelector(sid1);

			assertNull(conv.getIssuerAsString());
			assertTrue(Arrays.areEqual(conv.getSubjectKeyIdentifier(), (new DEROctetString(new byte[20])).getEncoded()));
			assertNull(conv.getSerialNumber());

			sid2 = toSelector.getCertificateHolderSelector(conv);

			assertEquals(sid1, sid2);
		}

		public static Test suite()
		{
			return new TestSuite(typeof(ConverterTest));
		}
	}

}
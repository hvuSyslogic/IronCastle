using System;

namespace org.bouncycastle.pkix.test
{

	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using BasicConstraints = org.bouncycastle.asn1.x509.BasicConstraints;
	using CRLReason = org.bouncycastle.asn1.x509.CRLReason;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using X509v1CertificateBuilder = org.bouncycastle.cert.X509v1CertificateBuilder;
	using X509v2CRLBuilder = org.bouncycastle.cert.X509v2CRLBuilder;
	using X509v3CertificateBuilder = org.bouncycastle.cert.X509v3CertificateBuilder;
	using JcaX509CRLConverter = org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
	using JcaX509CertificateConverter = org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
	using JcaX509ExtensionUtils = org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
	using JcaX509v1CertificateBuilder = org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
	using JcaX509v2CRLBuilder = org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
	using JcaX509v3CertificateBuilder = org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using JcaContentSignerBuilder = org.bouncycastle.@operator.jcajce.JcaContentSignerBuilder;

	public class TestUtil
	{
		public static BigInteger serialNumber = BigInteger.ONE;

		private static BigInteger allocateSerialNumber()
		{
			BigInteger _tmp = serialNumber;
			serialNumber = serialNumber.add(BigInteger.ONE);
			return _tmp;
		}

		public static X509Certificate makeTrustAnchor(KeyPair kp, string name)
		{
			X509v1CertificateBuilder v1CertGen = new JcaX509v1CertificateBuilder(new X500Name(name), allocateSerialNumber(), new DateTime(System.currentTimeMillis()), new DateTime(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)), new X500Name(name), kp.getPublic());

			JcaContentSignerBuilder contentSignerBuilder = (new JcaContentSignerBuilder("SHA256WithRSA")).setProvider("BC");

			X509Certificate cert = (new JcaX509CertificateConverter()).setProvider("BC").getCertificate(v1CertGen.build(contentSignerBuilder.build(kp.getPrivate())));

			cert.checkValidity(DateTime.Now);
			cert.verify(kp.getPublic());

			return cert;
		}

		public static X509Certificate makeCaCertificate(X509Certificate issuer, PrivateKey issuerKey, PublicKey subjectKey, string subject)
		{
			X509v3CertificateBuilder v3CertGen = new JcaX509v3CertificateBuilder(issuer.getSubjectX500Principal(), allocateSerialNumber(), new DateTime(System.currentTimeMillis()), new DateTime(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)), new X500Principal(subject), subjectKey);

			JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

			v3CertGen.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(subjectKey));

			v3CertGen.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(issuer));

			v3CertGen.addExtension(Extension.basicConstraints, false, new BasicConstraints(0));

			JcaContentSignerBuilder contentSignerBuilder = (new JcaContentSignerBuilder("SHA256WithRSA")).setProvider("BC");

			X509Certificate cert = (new JcaX509CertificateConverter()).setProvider("BC").getCertificate(v3CertGen.build(contentSignerBuilder.build(issuerKey)));

			cert.checkValidity(DateTime.Now);
			cert.verify(issuer.getPublicKey());

			return cert;
		}

		public static X509Certificate makeEeCertificate(bool withDistPoint, X509Certificate issuer, PrivateKey issuerKey, PublicKey subjectKey, string subject)
		{
			X509v3CertificateBuilder v3CertGen = new JcaX509v3CertificateBuilder(issuer.getSubjectX500Principal(), allocateSerialNumber(), new DateTime(System.currentTimeMillis()), new DateTime(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)), new X500Principal(subject), subjectKey);

			JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

			v3CertGen.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(subjectKey));

			v3CertGen.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(issuer));

			v3CertGen.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));

			if (withDistPoint)
			{
				v3CertGen.addExtension(Extension.cRLDistributionPoints, false, new DERSequence());
			}

			JcaContentSignerBuilder contentSignerBuilder = (new JcaContentSignerBuilder("SHA256WithRSA")).setProvider("BC");

			X509Certificate cert = (new JcaX509CertificateConverter()).setProvider("BC").getCertificate(v3CertGen.build(contentSignerBuilder.build(issuerKey)));

			cert.checkValidity(DateTime.Now);
			cert.verify(issuer.getPublicKey());

			return cert;
		}

		public static X509CRL makeCrl(X509Certificate issuer, PrivateKey sigKey, BigInteger revoked)
		{
			DateTime now = DateTime.Now;
			X509v2CRLBuilder crlGen = new JcaX509v2CRLBuilder(issuer.getSubjectX500Principal(), now);
			JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();

			crlGen.setNextUpdate(new DateTime(now.Ticks + 100000));

			crlGen.addCRLEntry(revoked, now, CRLReason.privilegeWithdrawn);

			crlGen.addExtension(Extension.authorityKeyIdentifier, false, extensionUtils.createAuthorityKeyIdentifier(issuer));

			return (new JcaX509CRLConverter()).setProvider("BC").getCRL(crlGen.build((new JcaContentSignerBuilder("SHA256WithRSA")).setProvider("BC").build(sigKey)));
		}
	}

}
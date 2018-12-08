using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.oiw;

using System;

namespace org.bouncycastle.asn1.test
{

	using ElGamalParameter = org.bouncycastle.asn1.oiw.ElGamalParameter;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using RSAPublicKey = org.bouncycastle.asn1.pkcs.RSAPublicKey;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using AuthorityKeyIdentifier = org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
	using CRLReason = org.bouncycastle.asn1.x509.CRLReason;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using Extensions = org.bouncycastle.asn1.x509.Extensions;
	using ExtensionsGenerator = org.bouncycastle.asn1.x509.ExtensionsGenerator;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using GeneralNames = org.bouncycastle.asn1.x509.GeneralNames;
	using IssuingDistributionPoint = org.bouncycastle.asn1.x509.IssuingDistributionPoint;
	using KeyUsage = org.bouncycastle.asn1.x509.KeyUsage;
	using SubjectKeyIdentifier = org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using TBSCertList = org.bouncycastle.asn1.x509.TBSCertList;
	using TBSCertificate = org.bouncycastle.asn1.x509.TBSCertificate;
	using Time = org.bouncycastle.asn1.x509.Time;
	using V1TBSCertificateGenerator = org.bouncycastle.asn1.x509.V1TBSCertificateGenerator;
	using V2TBSCertListGenerator = org.bouncycastle.asn1.x509.V2TBSCertListGenerator;
	using V3TBSCertificateGenerator = org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
	using Digest = org.bouncycastle.crypto.Digest;
	using SHA1Digest = org.bouncycastle.crypto.digests.SHA1Digest;
	using Arrays = org.bouncycastle.util.Arrays;
	using Base64 = org.bouncycastle.util.encoders.Base64;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class GenerationTest : SimpleTest
	{
		private byte[] v1Cert = Base64.decode("MIGtAgEBMA0GCSqGSIb3DQEBBAUAMCUxCzAJBgNVBAMMAkFVMRYwFAYDVQQKDA1Cb" + "3VuY3kgQ2FzdGxlMB4XDTcwMDEwMTAwMDAwMVoXDTcwMDEwMTAwMDAxMlowNjELMA" + "kGA1UEAwwCQVUxFjAUBgNVBAoMDUJvdW5jeSBDYXN0bGUxDzANBgNVBAsMBlRlc3Q" + "gMTAaMA0GCSqGSIb3DQEBAQUAAwkAMAYCAQECAQI=");

		private byte[] v3Cert = Base64.decode("MIIBSKADAgECAgECMA0GCSqGSIb3DQEBBAUAMCUxCzAJBgNVBAMMAkFVMRYwFAYD" + "VQQKDA1Cb3VuY3kgQ2FzdGxlMB4XDTcwMDEwMTAwMDAwMVoXDTcwMDEwMTAwMDAw" + "MlowNjELMAkGA1UEAwwCQVUxFjAUBgNVBAoMDUJvdW5jeSBDYXN0bGUxDzANBgNV" + "BAsMBlRlc3QgMjAYMBAGBisOBwIBATAGAgEBAgECAwQAAgEDo4GVMIGSMGEGA1Ud" + "IwEB/wRXMFWAFDZPdpHPzKi7o8EJokkQU2uqCHRRoTqkODA2MQswCQYDVQQDDAJB" + "VTEWMBQGA1UECgwNQm91bmN5IENhc3RsZTEPMA0GA1UECwwGVGVzdCAyggECMCAG" + "A1UdDgEB/wQWBBQ2T3aRz8you6PBCaJJEFNrqgh0UTALBgNVHQ8EBAMCBBA=");

		private byte[] v3CertNullSubject = Base64.decode("MIHGoAMCAQICAQIwDQYJKoZIhvcNAQEEBQAwJTELMAkGA1UEAwwCQVUxFjAUBgNVB" + "AoMDUJvdW5jeSBDYXN0bGUwHhcNNzAwMTAxMDAwMDAxWhcNNzAwMTAxMDAwMDAyWj" + "AAMBgwEAYGKw4HAgEBMAYCAQECAQIDBAACAQOjSjBIMEYGA1UdEQEB/wQ8MDqkODA" + "2MQswCQYDVQQDDAJBVTEWMBQGA1UECgwNQm91bmN5IENhc3RsZTEPMA0GA1UECwwG" + "VGVzdCAy");

		private byte[] v2CertList = Base64.decode("MIIBQwIBATANBgkqhkiG9w0BAQUFADAlMQswCQYDVQQDDAJBVTEWMBQGA1UECgwN" + "Qm91bmN5IENhc3RsZRcNNzAwMTAxMDAwMDAwWhcNNzAwMTAxMDAwMDAyWjAiMCAC" + "AQEXDTcwMDEwMTAwMDAwMVowDDAKBgNVHRUEAwoBCqCBxTCBwjBhBgNVHSMBAf8E" + "VzBVgBQ2T3aRz8you6PBCaJJEFNrqgh0UaE6pDgwNjELMAkGA1UEAwwCQVUxFjAU" + "BgNVBAoMDUJvdW5jeSBDYXN0bGUxDzANBgNVBAsMBlRlc3QgMoIBAjBDBgNVHRIE" + "PDA6pDgwNjELMAkGA1UEAwwCQVUxFjAUBgNVBAoMDUJvdW5jeSBDYXN0bGUxDzAN" + "BgNVBAsMBlRlc3QgMzAKBgNVHRQEAwIBATAMBgNVHRwBAf8EAjAA");

		private void tbsV1CertGen()
		{
			V1TBSCertificateGenerator gen = new V1TBSCertificateGenerator();
			DateTime startDate = new DateTime(1000);
			DateTime endDate = new DateTime(12000);

			gen.setSerialNumber(new ASN1Integer(1));

			gen.setStartDate(new Time(startDate));
			gen.setEndDate(new Time(endDate));

			gen.setIssuer(new X500Name("CN=AU,O=Bouncy Castle"));
			gen.setSubject(new X500Name("CN=AU,O=Bouncy Castle,OU=Test 1"));

			gen.setSignature(new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.md5WithRSAEncryption, DERNull.INSTANCE));

			SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.rsaEncryption, DERNull.INSTANCE), new RSAPublicKey(BigInteger.valueOf(1), BigInteger.valueOf(2)));

			gen.setSubjectPublicKeyInfo(info);

			TBSCertificate tbs = gen.generateTBSCertificate();
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			ASN1OutputStream aOut = new ASN1OutputStream(bOut);

			aOut.writeObject(tbs);

			if (!Arrays.areEqual(bOut.toByteArray(), v1Cert))
			{
				fail("failed v1 cert generation");
			}

			//
			// read back test
			//
			ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(v1Cert));
			ASN1Primitive o = aIn.readObject();

			bOut = new ByteArrayOutputStream();
			aOut = new ASN1OutputStream(bOut);

			aOut.writeObject(o);

			if (!Arrays.areEqual(bOut.toByteArray(), v1Cert))
			{
				fail("failed v1 cert read back test");
			}
		}

		private AuthorityKeyIdentifier createAuthorityKeyId(SubjectPublicKeyInfo info, X500Name name, int sNumber)
		{
			GeneralName genName = new GeneralName(name);
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(genName);

			return new AuthorityKeyIdentifier(info, GeneralNames.getInstance(new DERSequence(v)), BigInteger.valueOf(sNumber));
		}

		private void tbsV3CertGen()
		{
			V3TBSCertificateGenerator gen = new V3TBSCertificateGenerator();
			DateTime startDate = new DateTime(1000);
			DateTime endDate = new DateTime(2000);

			gen.setSerialNumber(new ASN1Integer(2));

			gen.setStartDate(new Time(startDate));
			gen.setEndDate(new Time(endDate));

			gen.setIssuer(new X500Name("CN=AU,O=Bouncy Castle"));
			gen.setSubject(new X500Name("CN=AU,O=Bouncy Castle,OU=Test 2"));

			gen.setSignature(new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.md5WithRSAEncryption, DERNull.INSTANCE));

			SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(OIWObjectIdentifiers_Fields.elGamalAlgorithm, new ElGamalParameter(BigInteger.valueOf(1), BigInteger.valueOf(2))), new ASN1Integer(3));

			gen.setSubjectPublicKeyInfo(info);

			//
			// add extensions
			//
			Extensions ex = new Extensions(new Extension[]
			{
				new Extension(Extension.authorityKeyIdentifier, true, new DEROctetString(createAuthorityKeyId(info, new X500Name("CN=AU,O=Bouncy Castle,OU=Test 2"), 2))),
				new Extension(Extension.subjectKeyIdentifier, true, new DEROctetString(new SubjectKeyIdentifier(getDigest(info)))),
				new Extension(Extension.keyUsage, false, new DEROctetString(new KeyUsage(KeyUsage.dataEncipherment)))
			});

			gen.setExtensions(ex);

			TBSCertificate tbs = gen.generateTBSCertificate();
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			ASN1OutputStream aOut = new ASN1OutputStream(bOut);

			aOut.writeObject(tbs);

			if (!Arrays.areEqual(bOut.toByteArray(), v3Cert))
			{
				fail("failed v3 cert generation");
			}

			//
			// read back test
			//
			ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(v3Cert));
			ASN1Primitive o = aIn.readObject();

			bOut = new ByteArrayOutputStream();
			aOut = new ASN1OutputStream(bOut);

			aOut.writeObject(o);

			if (!Arrays.areEqual(bOut.toByteArray(), v3Cert))
			{
				fail("failed v3 cert read back test");
			}
		}

		private void tbsV3CertGenWithNullSubject()
		{
			V3TBSCertificateGenerator gen = new V3TBSCertificateGenerator();
			DateTime startDate = new DateTime(1000);
			DateTime endDate = new DateTime(2000);

			gen.setSerialNumber(new ASN1Integer(2));

			gen.setStartDate(new Time(startDate));
			gen.setEndDate(new Time(endDate));

			gen.setIssuer(new X500Name("CN=AU,O=Bouncy Castle"));

			gen.setSignature(new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.md5WithRSAEncryption, DERNull.INSTANCE));

			SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(OIWObjectIdentifiers_Fields.elGamalAlgorithm, new ElGamalParameter(BigInteger.valueOf(1), BigInteger.valueOf(2))), new ASN1Integer(3));

			gen.setSubjectPublicKeyInfo(info);

			try
			{
				gen.generateTBSCertificate();
				fail("null subject not caught!");
			}
			catch (IllegalStateException e)
			{
				if (!e.getMessage().Equals("not all mandatory fields set in V3 TBScertificate generator"))
				{
					fail("unexpected exception", e);
				}
			}

			//
			// add extensions
			//

			Extensions ex = new Extensions(new Extension(Extension.subjectAlternativeName, true, new DEROctetString(new GeneralNames(new GeneralName(new X500Name("CN=AU,O=Bouncy Castle,OU=Test 2"))))));

			gen.setExtensions(ex);

			TBSCertificate tbs = gen.generateTBSCertificate();
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			ASN1OutputStream aOut = new ASN1OutputStream(bOut);

			aOut.writeObject(tbs);

			if (!Arrays.areEqual(bOut.toByteArray(), v3CertNullSubject))
			{
				fail("failed v3 null sub cert generation");
			}

			//
			// read back test
			//
			ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(v3CertNullSubject));
			ASN1Primitive o = aIn.readObject();

			bOut = new ByteArrayOutputStream();
			aOut = new ASN1OutputStream(bOut);

			aOut.writeObject(o);

			if (!Arrays.areEqual(bOut.toByteArray(), v3CertNullSubject))
			{
				fail("failed v3 null sub cert read back test");
			}
		}

		private void tbsV2CertListGen()
		{
			V2TBSCertListGenerator gen = new V2TBSCertListGenerator();

			gen.setIssuer(new X500Name("CN=AU,O=Bouncy Castle"));

			gen.addCRLEntry(new ASN1Integer(1), new Time(new DateTime(1000)), CRLReason.aACompromise);

			gen.setNextUpdate(new Time(new DateTime(2000)));

			gen.setThisUpdate(new Time(new DateTime(500)));

			gen.setSignature(new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.sha1WithRSAEncryption, DERNull.INSTANCE));

			//
			// extensions
			//
			SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(OIWObjectIdentifiers_Fields.elGamalAlgorithm, new ElGamalParameter(BigInteger.valueOf(1), BigInteger.valueOf(2))), new ASN1Integer(3));

			ExtensionsGenerator extGen = new ExtensionsGenerator();

			extGen.addExtension(Extension.authorityKeyIdentifier, true, createAuthorityKeyId(info, new X500Name("CN=AU,O=Bouncy Castle,OU=Test 2"), 2));
			extGen.addExtension(Extension.issuerAlternativeName, false, new GeneralNames(new GeneralName(new X500Name("CN=AU,O=Bouncy Castle,OU=Test 3"))));
			extGen.addExtension(Extension.cRLNumber, false, new ASN1Integer(1));
			extGen.addExtension(Extension.issuingDistributionPoint, true, IssuingDistributionPoint.getInstance(new DERSequence()));

			Extensions ex = extGen.generate();

			gen.setExtensions(ex);

			TBSCertList tbs = gen.generateTBSCertList();
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			ASN1OutputStream aOut = new ASN1OutputStream(bOut);

			aOut.writeObject(tbs);

			if (!Arrays.areEqual(bOut.toByteArray(), v2CertList))
			{
				JavaSystem.@out.println(StringHelper.NewString(Base64.encode(bOut.toByteArray())));
				fail("failed v2 cert list generation");
			}

			//
			// read back test
			//
			ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(v2CertList));
			ASN1Primitive o = aIn.readObject();

			bOut = new ByteArrayOutputStream();
			aOut = new ASN1OutputStream(bOut);

			aOut.writeObject(o);

			if (!Arrays.areEqual(bOut.toByteArray(), v2CertList))
			{
				fail("failed v2 cert list read back test");
			}

			//
			// check we can add a custom reason
			//
			gen.addCRLEntry(new ASN1Integer(1), new Time(new DateTime(1000)), CRLReason.aACompromise);

			//
			// check invalidity date
			gen.addCRLEntry(new ASN1Integer(2), new Time(new DateTime(1000)), CRLReason.affiliationChanged, new ASN1GeneralizedTime(new DateTime(2000)));

			TBSCertList crl = gen.generateTBSCertList();

			TBSCertList.CRLEntry[] entries = crl.getRevokedCertificates();
			for (int i = 0; i != entries.Length; i++)
			{
				TBSCertList.CRLEntry entry = entries[i];

				if (entry.getUserCertificate().Equals(new ASN1Integer(1)))
				{
					Extensions extensions = entry.getExtensions();
					Extension ext = extensions.getExtension(Extension.reasonCode);

					CRLReason r = CRLReason.getInstance(ext.getParsedValue());

					if (r.getValue().intValue() != CRLReason.aACompromise)
					{
						fail("reason code mismatch");
					}
				}
				else if (entry.getUserCertificate().Equals(new ASN1Integer(2)))
				{
					Extensions extensions = entry.getExtensions();
					Extension ext = extensions.getExtension(Extension.reasonCode);

					CRLReason r = CRLReason.getInstance(ext.getParsedValue());

					if (r.getValue().intValue() != CRLReason.affiliationChanged)
					{
						fail("reason code mismatch");
					}

					ext = extensions.getExtension(Extension.invalidityDate);

					ASN1GeneralizedTime t = ASN1GeneralizedTime.getInstance(ext.getParsedValue());

					try
					{
						if (!t.getDate().Equals(new DateTime(2000)))
						{
							fail("invalidity date mismatch");
						}
					}
					catch (ParseException e)
					{
						fail("can't parse date", e);
					}
				}
			}
		}

		public override void performTest()
		{
			tbsV1CertGen();
			tbsV3CertGen();
			tbsV3CertGenWithNullSubject();
			tbsV2CertListGen();
		}

		public override string getName()
		{
			return "Generation";
		}

		private static byte[] getDigest(SubjectPublicKeyInfo spki)
		{
			Digest digest = new SHA1Digest();
			byte[] resBuf = new byte[digest.getDigestSize()];

			byte[] bytes = spki.getPublicKeyData().getBytes();
			digest.update(bytes, 0, bytes.Length);
			digest.doFinal(resBuf, 0);
			return resBuf;
		}

		public static void Main(string[] args)
		{
			runTest(new GenerationTest());
		}
	}

}
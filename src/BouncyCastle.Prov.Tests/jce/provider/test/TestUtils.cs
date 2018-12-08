using org.bouncycastle.asn1.cryptopro;
using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.x9;
using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.jce.provider.test
{

	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using DERBitString = org.bouncycastle.asn1.DERBitString;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using AuthorityKeyIdentifier = org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
	using BasicConstraints = org.bouncycastle.asn1.x509.BasicConstraints;
	using CRLNumber = org.bouncycastle.asn1.x509.CRLNumber;
	using CRLReason = org.bouncycastle.asn1.x509.CRLReason;
	using Certificate = org.bouncycastle.asn1.x509.Certificate;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using Extensions = org.bouncycastle.asn1.x509.Extensions;
	using ExtensionsGenerator = org.bouncycastle.asn1.x509.ExtensionsGenerator;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using GeneralNames = org.bouncycastle.asn1.x509.GeneralNames;
	using KeyUsage = org.bouncycastle.asn1.x509.KeyUsage;
	using SubjectKeyIdentifier = org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using TBSCertificate = org.bouncycastle.asn1.x509.TBSCertificate;
	using Time = org.bouncycastle.asn1.x509.Time;
	using V1TBSCertificateGenerator = org.bouncycastle.asn1.x509.V1TBSCertificateGenerator;
	using V3TBSCertificateGenerator = org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
	using X509Extensions = org.bouncycastle.asn1.x509.X509Extensions;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using Digest = org.bouncycastle.crypto.Digest;
	using SHA1Digest = org.bouncycastle.crypto.digests.SHA1Digest;
	using X509V2CRLGenerator = org.bouncycastle.x509.X509V2CRLGenerator;
	using AuthorityKeyIdentifierStructure = org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;

	/// <summary>
	/// Test Utils
	/// </summary>
	public class TestUtils
	{
		private static AtomicLong serialNumber = new AtomicLong(System.currentTimeMillis());
		private static Map algIds = new HashMap();

		static TestUtils()
		{
			algIds.put("GOST3411withGOST3410", new AlgorithmIdentifier(CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_94));
			algIds.put("SHA1withRSA", new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.sha1WithRSAEncryption, DERNull.INSTANCE));
			algIds.put("SHA256withRSA", new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.sha256WithRSAEncryption, DERNull.INSTANCE));
			algIds.put("SHA1withECDSA", new AlgorithmIdentifier(X9ObjectIdentifiers_Fields.ecdsa_with_SHA1));
			algIds.put("SHA256withECDSA", new AlgorithmIdentifier(X9ObjectIdentifiers_Fields.ecdsa_with_SHA256));
		}

		public static X509Certificate createSelfSignedCert(string dn, string sigName, KeyPair keyPair)
		{
			return createSelfSignedCert(new X500Name(dn), sigName, keyPair);
		}

		public static X509Certificate createSelfSignedCert(X500Name dn, string sigName, KeyPair keyPair)
		{
			V1TBSCertificateGenerator certGen = new V1TBSCertificateGenerator();

			long time = System.currentTimeMillis();

			certGen.setSerialNumber(new ASN1Integer(serialNumber.getAndIncrement()));
			certGen.setIssuer(dn);
			certGen.setSubject(dn);
			certGen.setStartDate(new Time(new DateTime(time - 5000)));
			certGen.setEndDate(new Time(new DateTime(time + 30 * 60 * 1000)));
			certGen.setSignature((AlgorithmIdentifier)algIds.get(sigName));
			certGen.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));

			Signature sig = Signature.getInstance(sigName, "BC");

			sig.initSign(keyPair.getPrivate());

			sig.update(certGen.generateTBSCertificate().getEncoded(ASN1Encoding_Fields.DER));

			TBSCertificate tbsCert = certGen.generateTBSCertificate();

			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(tbsCert);
			v.add((AlgorithmIdentifier)algIds.get(sigName));
			v.add(new DERBitString(sig.sign()));

			return (X509Certificate)CertificateFactory.getInstance("X.509", "BC").generateCertificate(new ByteArrayInputStream((new DERSequence(v)).getEncoded(ASN1Encoding_Fields.DER)));
		}

		public static X509Certificate createCert(X500Name signerName, PrivateKey signerKey, string dn, string sigName, Extensions extensions, PublicKey pubKey)
		{
			return createCert(signerName, signerKey, new X500Name(dn), sigName, extensions, pubKey);
		}

		public static X509Certificate createCert(X500Name signerName, PrivateKey signerKey, X500Name dn, string sigName, Extensions extensions, PublicKey pubKey)
		{
			V3TBSCertificateGenerator certGen = new V3TBSCertificateGenerator();

			long time = System.currentTimeMillis();

			certGen.setSerialNumber(new ASN1Integer(serialNumber.getAndIncrement()));
			certGen.setIssuer(signerName);
			certGen.setSubject(dn);
			certGen.setStartDate(new Time(new DateTime(time - 5000)));
			certGen.setEndDate(new Time(new DateTime(time + 30 * 60 * 1000)));
			certGen.setSignature((AlgorithmIdentifier)algIds.get(sigName));
			certGen.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(pubKey.getEncoded()));
			certGen.setExtensions(extensions);

			Signature sig = Signature.getInstance(sigName, "BC");

			sig.initSign(signerKey);

			sig.update(certGen.generateTBSCertificate().getEncoded(ASN1Encoding_Fields.DER));

			TBSCertificate tbsCert = certGen.generateTBSCertificate();

			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(tbsCert);
			v.add((AlgorithmIdentifier)algIds.get(sigName));
			v.add(new DERBitString(sig.sign()));

			return (X509Certificate)CertificateFactory.getInstance("X.509", "BC").generateCertificate(new ByteArrayInputStream((new DERSequence(v)).getEncoded(ASN1Encoding_Fields.DER)));
		}

		/// <summary>
		/// Create a random 1024 bit RSA key pair
		/// </summary>
		public static KeyPair generateRSAKeyPair()
		{
			KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

			kpGen.initialize(1024, new SecureRandom());

			return kpGen.generateKeyPair();
		}

		public static X509Certificate generateRootCert(KeyPair pair)
		{
			return createSelfSignedCert("CN=Test CA Certificate", "SHA256withRSA", pair);
		}

		public static X509Certificate generateRootCert(KeyPair pair, X500Name dn)
		{
			return createSelfSignedCert(dn, "SHA256withRSA", pair);
		}

		public static X509Certificate generateIntermediateCert(PublicKey intKey, PrivateKey caKey, X509Certificate caCert)
		{
			return generateIntermediateCert(intKey, new X500Name("CN=Test Intermediate Certificate"), caKey, caCert);
		}

		public static X509Certificate generateIntermediateCert(PublicKey intKey, X500Name subject, PrivateKey caKey, X509Certificate caCert)
		{
			Certificate caCertLw = Certificate.getInstance(caCert.getEncoded());

			ExtensionsGenerator extGen = new ExtensionsGenerator();

			extGen.addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(getDigest(caCertLw.getSubjectPublicKeyInfo()), new GeneralNames(new GeneralName(caCertLw.getIssuer())), caCertLw.getSerialNumber().getValue()));
			extGen.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(getDigest(SubjectPublicKeyInfo.getInstance(intKey.getEncoded()))));
			extGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
			extGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));

			return createCert(caCertLw.getSubject(), caKey, subject, "SHA256withRSA", extGen.generate(), intKey);
		}

		public static X509Certificate generateEndEntityCert(PublicKey intKey, PrivateKey caKey, X509Certificate caCert)
		{
			return generateEndEntityCert(intKey, new X500Name("CN=Test End Certificate"), caKey, caCert);
		}

		public static X509Certificate generateEndEntityCert(PublicKey entityKey, X500Name subject, PrivateKey caKey, X509Certificate caCert)
		{
			Certificate caCertLw = Certificate.getInstance(caCert.getEncoded());

			ExtensionsGenerator extGen = new ExtensionsGenerator();

			extGen.addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(getDigest(caCertLw.getSubjectPublicKeyInfo()), new GeneralNames(new GeneralName(caCertLw.getIssuer())), caCertLw.getSerialNumber().getValue()));
			extGen.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(getDigest(entityKey.getEncoded())));
			extGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
			extGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));

			return createCert(caCertLw.getSubject(), caKey, subject, "SHA256withRSA", extGen.generate(), entityKey);
		}

		public static X509CRL createCRL(X509Certificate caCert, PrivateKey caKey, BigInteger serialNumber)
		{
			X509V2CRLGenerator crlGen = new X509V2CRLGenerator();
			DateTime now = DateTime.Now;
			BigInteger revokedSerialNumber = BigInteger.valueOf(2);

			crlGen.setIssuerDN(PrincipalUtil.getSubjectX509Principal(caCert));

			crlGen.setThisUpdate(now);
			crlGen.setNextUpdate(new DateTime(now.Ticks + 100000));
			crlGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

			crlGen.addCRLEntry(serialNumber, now, CRLReason.privilegeWithdrawn);

			crlGen.addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(caCert));
			crlGen.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(1)));

			return crlGen.generate(caKey, "BC");
		}

		public static X509Certificate createExceptionCertificate(bool exceptionOnEncode)
		{
			return new ExceptionCertificate(exceptionOnEncode);
		}

		public static X500Name getCertIssuer(X509Certificate x509Certificate)
		{
			return TBSCertificate.getInstance(x509Certificate.getTBSCertificate()).getIssuer();
		}

		public static X500Name getCertSubject(X509Certificate x509Certificate)
		{
			return TBSCertificate.getInstance(x509Certificate.getTBSCertificate()).getSubject();
		}

		public class ExceptionCertificate : X509Certificate
		{
			internal bool _exceptionOnEncode;

			public ExceptionCertificate(bool exceptionOnEncode)
			{
				_exceptionOnEncode = exceptionOnEncode;
			}

			public virtual void checkValidity()
			{
				throw new CertificateNotYetValidException();
			}

			public virtual void checkValidity(DateTime date)
			{
				throw new CertificateExpiredException();
			}

			public virtual int getVersion()
			{
				return 0;
			}

			public virtual BigInteger getSerialNumber()
			{
				return null;
			}

			public virtual Principal getIssuerDN()
			{
				return null;
			}

			public virtual Principal getSubjectDN()
			{
				return null;
			}

			public virtual DateTime getNotBefore()
			{
				return null;
			}

			public virtual DateTime getNotAfter()
			{
				return null;
			}

			public virtual byte[] getTBSCertificate()
			{
				throw new CertificateEncodingException();
			}

			public virtual byte[] getSignature()
			{
				return new byte[0];
			}

			public virtual string getSigAlgName()
			{
				return null;
			}

			public virtual string getSigAlgOID()
			{
				return null;
			}

			public virtual byte[] getSigAlgParams()
			{
				return new byte[0];
			}

			public virtual bool[] getIssuerUniqueID()
			{
				return new bool[0];
			}

			public virtual bool[] getSubjectUniqueID()
			{
				return new bool[0];
			}

			public virtual bool[] getKeyUsage()
			{
				return new bool[0];
			}

			public virtual int getBasicConstraints()
			{
				return 0;
			}

			public virtual byte[] getEncoded()
			{
				if (_exceptionOnEncode)
				{
					throw new CertificateEncodingException();
				}

				return new byte[0];
			}

			public virtual void verify(PublicKey key)
			{
				throw new CertificateException();
			}

			public virtual void verify(PublicKey key, string sigProvider)
			{
				throw new CertificateException();
			}

			public override string ToString()
			{
				return null;
			}

			public virtual PublicKey getPublicKey()
			{
				return null;
			}

			public virtual bool hasUnsupportedCriticalExtension()
			{
				return false;
			}

			public virtual Set getCriticalExtensionOIDs()
			{
				return null;
			}

			public virtual Set getNonCriticalExtensionOIDs()
			{
				return null;
			}

			public virtual byte[] getExtensionValue(string oid)
			{
				return new byte[0];
			}

		}

		private static byte[] getDigest(SubjectPublicKeyInfo spki)
		{
			return getDigest(spki.getPublicKeyData().getBytes());
		}

		private static byte[] getDigest(byte[] bytes)
		{
			Digest digest = new SHA1Digest();
			byte[] resBuf = new byte[digest.getDigestSize()];

			digest.update(bytes, 0, bytes.Length);
			digest.doFinal(resBuf, 0);
			return resBuf;
		}

		public class AtomicLong
		{
			internal long value;

			public AtomicLong(long value)
			{
				this.value = value;
			}

			public virtual long getAndIncrement()
			{
				lock (this)
				{
					return value++;
				}
			}
		}
	}

}
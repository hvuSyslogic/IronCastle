using System;

namespace org.bouncycastle.cert.ocsp.test
{

	using AuthorityKeyIdentifier = org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
	using BasicConstraints = org.bouncycastle.asn1.x509.BasicConstraints;
	using SubjectKeyIdentifier = org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using X509Extensions = org.bouncycastle.asn1.x509.X509Extensions;
	using X509Name = org.bouncycastle.asn1.x509.X509Name;
	using BcX509ExtensionUtils = org.bouncycastle.cert.bc.BcX509ExtensionUtils;
	using X509V3CertificateGenerator = org.bouncycastle.x509.X509V3CertificateGenerator;

	public class OCSPTestUtil
	{

		public static SecureRandom rand;
		public static KeyPairGenerator kpg, eckpg;
		public static KeyGenerator desede128kg;
		public static KeyGenerator desede192kg;
		public static KeyGenerator rc240kg;
		public static KeyGenerator rc264kg;
		public static KeyGenerator rc2128kg;
		public static BigInteger serialNumber;

		public const bool DEBUG = true;

		static OCSPTestUtil()
		{
			try
			{
				rand = new SecureRandom();

				kpg = KeyPairGenerator.getInstance("RSA", "BC");
				kpg.initialize(1024, rand);

				serialNumber = new BigInteger("1");

				eckpg = KeyPairGenerator.getInstance("ECDSA", "BC");
				eckpg.initialize(192, rand);
			}
			catch (Exception ex)
			{
				throw new RuntimeException(ex.ToString());
			}
		}

		public static KeyPair makeKeyPair()
		{
			return kpg.generateKeyPair();
		}

		public static KeyPair makeECKeyPair()
		{
			return eckpg.generateKeyPair();
		}

		public static X509Certificate makeCertificate(KeyPair _subKP, string _subDN, KeyPair _issKP, string _issDN)
		{

			return makeCertificate(_subKP, _subDN, _issKP, _issDN, false);
		}

		public static X509Certificate makeECDSACertificate(KeyPair _subKP, string _subDN, KeyPair _issKP, string _issDN)
		{

			return makeECDSACertificate(_subKP, _subDN, _issKP, _issDN, false);
		}

		public static X509Certificate makeCACertificate(KeyPair _subKP, string _subDN, KeyPair _issKP, string _issDN)
		{

			return makeCertificate(_subKP, _subDN, _issKP, _issDN, true);
		}

		public static X509Certificate makeCertificate(KeyPair _subKP, string _subDN, KeyPair _issKP, string _issDN, bool _ca)
		{
			return makeCertificate(_subKP,_subDN, _issKP, _issDN, "MD5withRSA", _ca);
		}

		public static X509Certificate makeECDSACertificate(KeyPair _subKP, string _subDN, KeyPair _issKP, string _issDN, bool _ca)
		{
			return makeCertificate(_subKP,_subDN, _issKP, _issDN, "SHA1WithECDSA", _ca);
		}

		public static X509Certificate makeCertificate(KeyPair _subKP, string _subDN, KeyPair _issKP, string _issDN, string algorithm, bool _ca)
		{

			PublicKey _subPub = _subKP.getPublic();
			PrivateKey _issPriv = _issKP.getPrivate();
			PublicKey _issPub = _issKP.getPublic();

			X509V3CertificateGenerator _v3CertGen = new X509V3CertificateGenerator();

			_v3CertGen.reset();
			_v3CertGen.setSerialNumber(allocateSerialNumber());
			_v3CertGen.setIssuerDN(new X509Name(_issDN));
			_v3CertGen.setNotBefore(new DateTime(System.currentTimeMillis()));
			_v3CertGen.setNotAfter(new DateTime(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)));
			_v3CertGen.setSubjectDN(new X509Name(_subDN));
			_v3CertGen.setPublicKey(_subPub);
			_v3CertGen.setSignatureAlgorithm(algorithm);

			_v3CertGen.addExtension(X509Extensions.SubjectKeyIdentifier, false, createSubjectKeyId(_subPub));

			_v3CertGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, createAuthorityKeyId(_issPub));

			_v3CertGen.addExtension(X509Extensions.BasicConstraints, false, new BasicConstraints(_ca));

			X509Certificate _cert = _v3CertGen.generate(_issPriv);

			_cert.checkValidity(DateTime.Now);
			_cert.verify(_issPub);

			return _cert;
		}

		/*
		 * 
		 * INTERNAL METHODS
		 * 
		 */

		private static AuthorityKeyIdentifier createAuthorityKeyId(PublicKey _pubKey)
		{
			SubjectPublicKeyInfo _info = SubjectPublicKeyInfo.getInstance(_pubKey.getEncoded());

			return new AuthorityKeyIdentifier(_info);
		}

		private static SubjectKeyIdentifier createSubjectKeyId(PublicKey _pubKey)
		{
			return (new BcX509ExtensionUtils()).createSubjectKeyIdentifier(SubjectPublicKeyInfo.getInstance(_pubKey.getEncoded()));
		}

		private static BigInteger allocateSerialNumber()
		{
			BigInteger _tmp = serialNumber;
			serialNumber = serialNumber.add(BigInteger.valueOf(1));
			return _tmp;
		}
	}

}
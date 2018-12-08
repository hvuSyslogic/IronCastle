using System;

namespace org.bouncycastle.tsp.test
{


	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using AuthorityKeyIdentifier = org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
	using BasicConstraints = org.bouncycastle.asn1.x509.BasicConstraints;
	using ExtendedKeyUsage = org.bouncycastle.asn1.x509.ExtendedKeyUsage;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using KeyPurposeId = org.bouncycastle.asn1.x509.KeyPurposeId;
	using SubjectKeyIdentifier = org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
	using X509Name = org.bouncycastle.asn1.x509.X509Name;
	using JcaX509ExtensionUtils = org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
	using Base64 = org.bouncycastle.util.encoders.Base64;
	using X509V3CertificateGenerator = org.bouncycastle.x509.X509V3CertificateGenerator;

	public class TSPTestUtil
	{

		public static SecureRandom rand = new SecureRandom();

		public static KeyPairGenerator kpg;

		public static KeyGenerator desede128kg;

		public static KeyGenerator desede192kg;

		public static KeyGenerator rc240kg;

		public static KeyGenerator rc264kg;

		public static KeyGenerator rc2128kg;

		public static BigInteger serialNumber = BigInteger.ONE;

		public const bool DEBUG = true;

		public static ASN1ObjectIdentifier EuroPKI_TSA_Test_Policy = new ASN1ObjectIdentifier("1.3.6.1.4.1.5255.5.1");

		public static JcaX509ExtensionUtils extUtils;

		static TSPTestUtil()
		{
			try
			{
				rand = new SecureRandom();

				kpg = KeyPairGenerator.getInstance("RSA", "BC");
				kpg.initialize(1024, rand);

				desede128kg = KeyGenerator.getInstance("DESEDE", "BC");
				desede128kg.init(112, rand);

				desede192kg = KeyGenerator.getInstance("DESEDE", "BC");
				desede192kg.init(168, rand);

				rc240kg = KeyGenerator.getInstance("RC2", "BC");
				rc240kg.init(40, rand);

				rc264kg = KeyGenerator.getInstance("RC2", "BC");
				rc264kg.init(64, rand);

				rc2128kg = KeyGenerator.getInstance("RC2", "BC");
				rc2128kg.init(128, rand);

				serialNumber = new BigInteger("1");

				extUtils = new JcaX509ExtensionUtils();

			}
			catch (Exception ex)
			{
				throw new RuntimeException(ex.ToString());
			}
		}

		public static string dumpBase64(byte[] data)
		{
			StringBuffer buf = new StringBuffer();

			data = Base64.encode(data);

			for (int i = 0; i < data.Length; i += 64)
			{
				if (i + 64 < data.Length)
				{
					buf.append(StringHelper.NewString(data, i, 64));
				}
				else
				{
					buf.append(StringHelper.NewString(data, i, data.Length - i));
				}
				buf.append('\n');
			}

			return buf.ToString();
		}

		public static KeyPair makeKeyPair()
		{
			return kpg.generateKeyPair();
		}

		public static SecretKey makeDesede128Key()
		{
			return desede128kg.generateKey();
		}

		public static SecretKey makeDesede192Key()
		{
			return desede192kg.generateKey();
		}

		public static SecretKey makeRC240Key()
		{
			return rc240kg.generateKey();
		}

		public static SecretKey makeRC264Key()
		{
			return rc264kg.generateKey();
		}

		public static SecretKey makeRC2128Key()
		{
			return rc2128kg.generateKey();
		}

		public static X509Certificate makeCertificate(KeyPair _subKP, string _subDN, KeyPair _issKP, string _issDN)
		{

			return makeCertificate(_subKP, _subDN, _issKP, _issDN, false);
		}

		public static X509Certificate makeCACertificate(KeyPair _subKP, string _subDN, KeyPair _issKP, string _issDN)
		{

			return makeCertificate(_subKP, _subDN, _issKP, _issDN, true);
		}

		public static X509Certificate makeCertificate(KeyPair _subKP, string _subDN, KeyPair _issKP, string _issDN, bool _ca)
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
			_v3CertGen.setSignatureAlgorithm("MD5WithRSAEncryption");

			_v3CertGen.addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyId(_subPub));

			_v3CertGen.addExtension(Extension.authorityKeyIdentifier, false, createAuthorityKeyId(_issPub));

			if (_ca)
			{
				_v3CertGen.addExtension(Extension.basicConstraints, false, new BasicConstraints(_ca));
			}
			else
			{
				_v3CertGen.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));
			}

			X509Certificate _cert = _v3CertGen.generate(_issPriv);

			_cert.checkValidity(DateTime.Now);
			_cert.verify(_issPub);

			return _cert;
		}

		/*  
		 *  
		 *  INTERNAL METHODS
		 *  
		 */


		private static AuthorityKeyIdentifier createAuthorityKeyId(PublicKey _pubKey)
		{
			return extUtils.createAuthorityKeyIdentifier(_pubKey);
		}

		private static SubjectKeyIdentifier createSubjectKeyId(PublicKey _pubKey)
		{
			return extUtils.createSubjectKeyIdentifier(_pubKey);
		}

		private static BigInteger allocateSerialNumber()
		{
			BigInteger _tmp = serialNumber;
			serialNumber = serialNumber.add(BigInteger.ONE);
			return _tmp;
		}
	}

}
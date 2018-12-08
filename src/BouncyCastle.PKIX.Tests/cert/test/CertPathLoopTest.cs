using System;

namespace org.bouncycastle.cert.test
{

	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using BasicConstraints = org.bouncycastle.asn1.x509.BasicConstraints;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using KeyUsage = org.bouncycastle.asn1.x509.KeyUsage;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using JcaX509CRLConverter = org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
	using JcaX509CertificateConverter = org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using ContentSigner = org.bouncycastle.@operator.ContentSigner;
	using JcaContentSignerBuilder = org.bouncycastle.@operator.jcajce.JcaContentSignerBuilder;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;


	/// <summary>
	/// BC bug test case.
	/// </summary>
	public class CertPathLoopTest : SimpleTest
	{
		/// <summary>
		/// List of trust anchors
		/// </summary>
		private static Set<TrustAnchor> taSet;
		/// <summary>
		/// List of certificates and CRLs
		/// </summary>
		private static List<object> otherList;

		/// <summary>
		/// Asks the user about the configuration he want's to test
		/// </summary>
		/// <param name="caA"> </param>
		/// <param name="caB"> </param>
		private static void checkUseDistinctCAs(CA caA, CA caB)
		{
			//Standard configuration : everything in caA
			taSet = new HashSet<TrustAnchor>();
			taSet.add(caA.ta);
			otherList = new ArrayList<object>();
			otherList.add(caA.acCertCrl);
			otherList.add(caA.crl);
			//User specified configuration : parts of caB

			taSet.add(caB.ta);
			otherList.add(caB.acCertCrl);
			otherList.add(caB.crl);
		}

		/// <summary>
		/// Creates a collection cert store
		/// </summary>
		internal static CertStore getStore(Collection col)
		{
			CertStoreParameters csp = new CollectionCertStoreParameters(col);
			return CertStore.getInstance("Collection", csp);
		}

		public override string getName()
		{
			return "CertPath Loop Test";
		}

		public override void performTest()
		{
				  //Add the provider
			Security.addProvider(new BouncyCastleProvider());
			//Generate two Cert authorities
			CA caA = new CA();
			CA caB = new CA();
			//Ask the user the conf he want's to test
			checkUseDistinctCAs(caA, caB);

			//Let's create a target cert under caA
			X509CertSelector target = new X509CertSelector();
			target.setCertificate(caA.makeNewCert());
			//create control parameters
			PKIXBuilderParameters @params = new PKIXBuilderParameters(taSet, target);
			@params.addCertStore(getStore(Collections.singleton(target.getCertificate())));
			@params.addCertStore(getStore(otherList));
			//enable revocation check
			@params.setRevocationEnabled(true);

			//Lets Build the path
			try
			{
				CertPathBuilderResult cpbr = CertPathBuilder.getInstance("PKIX", "BC").build(@params);

				fail("invalid path build");
			}
			catch (CertPathBuilderException e)
			{
				if (!e.InnerException.Message.Equals("CertPath for CRL signer failed to validate."))
				{
					fail("Exception thrown, but wrong one", e.InnerException);
				}
			}
		}

		/// <summary>
		/// Class simulating a certification authority
		/// </summary>
		public class CA
		{
			/// <summary>
			/// key pair generator
			/// </summary>
			internal static readonly KeyPairGenerator kpg;

			static CA()
			{
				try
				{
					kpg = KeyPairGenerator.getInstance("RSA");
					//Key size doesn't matter, smaller == Faster
					kpg.initialize(512);
				}
				catch (NoSuchAlgorithmException e)
				{
					throw new RuntimeException(e);
				}
			}

			/// <summary>
			/// KeyPair signing certificates
			/// </summary>
			internal KeyPair caCertKp;
			/// <summary>
			/// KeyPair signing CRLs
			/// </summary>
			internal KeyPair caCrlKp;
			internal TrustAnchor ta;
			/// <summary>
			/// Subject of this CA
			/// </summary>
			internal X500Name acSubject;
			/// <summary>
			/// Certificate signing certificates
			/// </summary>
			internal X509Certificate acCertAc;
			/// <summary>
			/// Certificate signing CRLs
			/// </summary>
			internal X509Certificate acCertCrl;
			/// <summary>
			/// the CRL
			/// </summary>
			internal X509CRL crl;
			/// <summary>
			/// Signers
			/// </summary>
			internal ContentSigner caCrlSigner, caCertSigner;
			/// <summary>
			/// Serial number counter
			/// </summary>
			internal int counter = 1;

			/// <summary>
			/// Constructor
			/// </summary>
			public CA()
			{
				//Init both keypairs
				caCertKp = kpg.generateKeyPair();
				caCrlKp = kpg.generateKeyPair();
				//subject
				acSubject = new X500Name("CN=AC_0");
				//validity
				GregorianCalendar gc = new GregorianCalendar();
				DateTime notBefore = gc.getTime();
				gc.add(GregorianCalendar.DAY_OF_YEAR, 1);
				DateTime notAfter = gc.getTime();
				//first signer
				caCertSigner = (new JcaContentSignerBuilder("SHA1withRSA")).build(caCertKp.getPrivate());
				//top level : issuer is self
				X500Name issuer = acSubject;
				//reserved for future use (another test case)
				ContentSigner thisAcSigner = caCertSigner;
				//reserved for future use (another test case)
				//First certificate: Certificate authority (BasicConstraints=true) but not CRLSigner
				X509CertificateHolder certH = (new X509v3CertificateBuilder(issuer, BigInteger.valueOf(counter++), notBefore, notAfter, acSubject, getPublicKeyInfo(caCertKp.getPublic()))).addExtension(Extension.basicConstraints, true, new BasicConstraints(true)).addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign)).build(thisAcSigner);
				//lets convert to X509Certificate
				acCertAc = convert(certH);
				//and build a trust Anchor
				ta = new TrustAnchor(acCertAc, null);

				//Second signer
				caCrlSigner = (new JcaContentSignerBuilder("SHA1withRSA")).build(caCrlKp.getPrivate());
				//second certificate: CRLSigner but not Certificate authority (BasicConstraints=false)
				certH = (new X509v3CertificateBuilder(issuer, BigInteger.valueOf(counter++), notBefore, notAfter, acSubject, getPublicKeyInfo(caCrlKp.getPublic()))).addExtension(Extension.basicConstraints, false, new BasicConstraints(false)).addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.cRLSign)).build(thisAcSigner);
				//lets convert to X509Certificate
				acCertCrl = convert(certH);
				//And create the CRL
				X509CRLHolder crlH = (new X509v2CRLBuilder(acSubject, notBefore)).setNextUpdate(notAfter).build(caCrlSigner);
				//lets convert to X509CRL
				crl = convert(crlH);
			}

			/// <summary>
			/// Creates a child certificate
			/// </summary>
			public virtual X509Certificate makeNewCert()
			{
				//private key doesn't matter for the test
				PublicKey publicKey = kpg.generateKeyPair().getPublic();
				//Validity
				GregorianCalendar gc = new GregorianCalendar();
				DateTime notBefore = gc.getTime();
				gc.add(GregorianCalendar.DAY_OF_YEAR, 1);
				DateTime notAfter = gc.getTime();
				//serial
				BigInteger certSerial = BigInteger.valueOf(counter++);
				//Distinct name based on the serial
				X500Name subject = new X500Name("CN=EU_" + certSerial.ToString());
				//End user certificate, not allowed to do anything
				X509CertificateHolder enUserCertH = (new X509v3CertificateBuilder(acSubject, certSerial, notBefore, notAfter, subject, getPublicKeyInfo(publicKey))).addExtension(Extension.basicConstraints, false, new BasicConstraints(false)).addExtension(Extension.keyUsage, true, new KeyUsage(0)).build(caCertSigner);

				//lets convert to X509Certificate
				return convert(enUserCertH);
			}


			/// <summary>
			/// convert to X509Certificate
			/// </summary>
			internal static X509Certificate convert(X509CertificateHolder h)
			{
				return (new JcaX509CertificateConverter()).getCertificate(h);
			}

			/// <summary>
			/// convert to X509CRL
			/// </summary>
			internal static X509CRL convert(X509CRLHolder h)
			{
				return (new JcaX509CRLConverter()).getCRL(h);
			}

			/// <summary>
			/// convert to SubjectPublicKeyInfo
			/// </summary>
			internal static SubjectPublicKeyInfo getPublicKeyInfo(PublicKey k)
			{
				return SubjectPublicKeyInfo.getInstance(k.getEncoded());
			}
		}

		public static void Main(string[] args)
		{
			runTest(new CertPathLoopTest());
		}
	}

}
using System;

namespace org.bouncycastle.mail.smime.examples
{


	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using AttributeTable = org.bouncycastle.asn1.cms.AttributeTable;
	using IssuerAndSerialNumber = org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
	using SMIMECapabilitiesAttribute = org.bouncycastle.asn1.smime.SMIMECapabilitiesAttribute;
	using SMIMECapability = org.bouncycastle.asn1.smime.SMIMECapability;
	using SMIMECapabilityVector = org.bouncycastle.asn1.smime.SMIMECapabilityVector;
	using SMIMEEncryptionKeyPreferenceAttribute = org.bouncycastle.asn1.smime.SMIMEEncryptionKeyPreferenceAttribute;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using X509v3CertificateBuilder = org.bouncycastle.cert.X509v3CertificateBuilder;
	using JcaCertStore = org.bouncycastle.cert.jcajce.JcaCertStore;
	using JcaX509CertificateConverter = org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
	using JcaX509ExtensionUtils = org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
	using JcaX509v3CertificateBuilder = org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
	using JcaSimpleSignerInfoGeneratorBuilder = org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using JcaContentSignerBuilder = org.bouncycastle.@operator.jcajce.JcaContentSignerBuilder;
	using Store = org.bouncycastle.util.Store;

	/// <summary>
	/// a simple example that creates a single signed mail message.
	/// </summary>
	public class CreateLargeSignedMail
	{
		//
		// certificate serial number seed.
		//
		internal static int serialNo = 1;

		/// <summary>
		/// create a basic X509 certificate from the given keys
		/// </summary>
		internal static X509Certificate makeCertificate(KeyPair subKP, string subDN, KeyPair issKP, string issDN)
		{
			PublicKey subPub = subKP.getPublic();
			PrivateKey issPriv = issKP.getPrivate();
			PublicKey issPub = issKP.getPublic();

			JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
			X509v3CertificateBuilder v3CertGen = new JcaX509v3CertificateBuilder(new X500Name(issDN), BigInteger.valueOf(serialNo++), new DateTime(System.currentTimeMillis()), new DateTime(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)), new X500Name(subDN), subPub);

			v3CertGen.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(subPub));

			v3CertGen.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(issPub));

			return (new JcaX509CertificateConverter()).setProvider("BC").getCertificate(v3CertGen.build((new JcaContentSignerBuilder("MD5withRSA")).setProvider("BC").build(issPriv)));
		}

		public static void Main(string[] args)
		{
			//
			// set up our certs
			//
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");

			kpg.initialize(1024, new SecureRandom());

			//
			// cert that issued the signing certificate
			//
			string signDN = "O=Bouncy Castle, C=AU";
			KeyPair signKP = kpg.generateKeyPair();
			X509Certificate signCert = makeCertificate(signKP, signDN, signKP, signDN);

			//
			// cert we sign against
			//
			string origDN = "CN=Eric H. Echidna, E=eric@bouncycastle.org, O=Bouncy Castle, C=AU";
			KeyPair origKP = kpg.generateKeyPair();
			X509Certificate origCert = makeCertificate(origKP, origDN, signKP, signDN);

			List certList = new ArrayList();

			certList.add(origCert);
			certList.add(signCert);

			//
			// create a CertStore containing the certificates we want carried
			// in the signature
			//
			Store certs = new JcaCertStore(certList);

			//
			// create some smime capabilities in case someone wants to respond
			//
			ASN1EncodableVector signedAttrs = new ASN1EncodableVector();
			SMIMECapabilityVector caps = new SMIMECapabilityVector();

			caps.addCapability(SMIMECapability.dES_EDE3_CBC);
			caps.addCapability(SMIMECapability.rC2_CBC, 128);
			caps.addCapability(SMIMECapability.dES_CBC);

			signedAttrs.add(new SMIMECapabilitiesAttribute(caps));

			//
			// add an encryption key preference for encrypted responses -
			// normally this would be different from the signing certificate...
			//
			IssuerAndSerialNumber issAndSer = new IssuerAndSerialNumber(new X500Name(signDN), origCert.getSerialNumber());

			signedAttrs.add(new SMIMEEncryptionKeyPreferenceAttribute(issAndSer));

			//
			// create the generator for creating an smime/signed message
			//
			SMIMESignedGenerator gen = new SMIMESignedGenerator();

			//
			// add a signer to the generator - this specifies we are using SHA1 and
			// adding the smime attributes above to the signed attributes that
			// will be generated as part of the signature. The encryption algorithm
			// used is taken from the key - in this RSA with PKCS1Padding
			//
			gen.addSignerInfoGenerator((new JcaSimpleSignerInfoGeneratorBuilder()).setProvider("BC").setSignedAttributeGenerator(new AttributeTable(signedAttrs)).build("SHA1withRSA", origKP.getPrivate(), origCert));

			//
			// add our pool of certs and cerls (if any) to go with the signature
			//
			gen.addCertificates(certs);

			//
			// create the base for our message
			//
			MimeBodyPart msg = new MimeBodyPart();

			msg.setDataHandler(new DataHandler(new FileDataSource(new File(args[0]))));
			msg.setHeader("Content-Type", "application/octet-stream");
			msg.setHeader("Content-Transfer-Encoding", "base64");

			//
			// extract the multipart object from the SMIMESigned object.
			//
			MimeMultipart mm = gen.generate(msg);

			//
			// Get a Session object and create the mail message
			//
			Properties props = System.getProperties();
			Session session = Session.getDefaultInstance(props, null);

			Address fromUser = new InternetAddress(@"""Eric H. Echidna""<eric@bouncycastle.org>");
			Address toUser = new InternetAddress("example@bouncycastle.org");

			MimeMessage body = new MimeMessage(session);
			body.setFrom(fromUser);
			body.setRecipient(Message.RecipientType.TO, toUser);
			body.setSubject("example signed message");
			body.setContent(mm, mm.getContentType());
			body.saveChanges();

			body.writeTo(new FileOutputStream("signed.message"));
		}
	}

}
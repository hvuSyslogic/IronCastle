using org.bouncycastle.asn1.rosstandart;

using System;

namespace org.bouncycastle.cert.test
{

	using RosstandartObjectIdentifiers = org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using BasicConstraints = org.bouncycastle.asn1.x509.BasicConstraints;
	using ExtendedKeyUsage = org.bouncycastle.asn1.x509.ExtendedKeyUsage;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using KeyPurposeId = org.bouncycastle.asn1.x509.KeyPurposeId;
	using KeyUsage = org.bouncycastle.asn1.x509.KeyUsage;
	using CMSException = org.bouncycastle.cms.CMSException;
	using CMSProcessableByteArray = org.bouncycastle.cms.CMSProcessableByteArray;
	using CMSSignedData = org.bouncycastle.cms.CMSSignedData;
	using CMSSignedDataGenerator = org.bouncycastle.cms.CMSSignedDataGenerator;
	using CMSTypedData = org.bouncycastle.cms.CMSTypedData;
	using SignerId = org.bouncycastle.cms.SignerId;
	using SignerInfoGenerator = org.bouncycastle.cms.SignerInfoGenerator;
	using SignerInformation = org.bouncycastle.cms.SignerInformation;
	using SignerInformationStore = org.bouncycastle.cms.SignerInformationStore;
	using SignerInformationVerifier = org.bouncycastle.cms.SignerInformationVerifier;
	using JcaSignerInfoGeneratorBuilder = org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
	using JcaSimpleSignerInfoVerifierBuilder = org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using ECPrivateKeyParameters = org.bouncycastle.crypto.@params.ECPrivateKeyParameters;
	using ECPublicKeyParameters = org.bouncycastle.crypto.@params.ECPublicKeyParameters;
	using SubjectPublicKeyInfoFactory = org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
	using ECPrivateKey = org.bouncycastle.jce.interfaces.ECPrivateKey;
	using ECPublicKey = org.bouncycastle.jce.interfaces.ECPublicKey;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using ECNamedCurveGenParameterSpec = org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
	using ECParameterSpec = org.bouncycastle.jce.spec.ECParameterSpec;
	using ContentSigner = org.bouncycastle.@operator.ContentSigner;
	using DefaultDigestAlgorithmIdentifierFinder = org.bouncycastle.@operator.DefaultDigestAlgorithmIdentifierFinder;
	using DefaultSignatureAlgorithmIdentifierFinder = org.bouncycastle.@operator.DefaultSignatureAlgorithmIdentifierFinder;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using BcContentSignerBuilder = org.bouncycastle.@operator.bc.BcContentSignerBuilder;
	using BcECContentSignerBuilder = org.bouncycastle.@operator.bc.BcECContentSignerBuilder;
	using JcaContentSignerBuilder = org.bouncycastle.@operator.jcajce.JcaContentSignerBuilder;
	using JcaDigestCalculatorProviderBuilder = org.bouncycastle.@operator.jcajce.JcaDigestCalculatorProviderBuilder;
	using Store = org.bouncycastle.util.Store;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;
	using Test = org.bouncycastle.util.test.Test;
	using TestResult = org.bouncycastle.util.test.TestResult;


	public class GOST3410_2012CMSTest : SimpleTest
	{

		public override string getName()
		{
			return "GOST3410 2012 CMS TEST";
		}

		public override void performTest()
		{
			if (Security.getProvider("BC").containsKey("KeyFactory.ECGOST3410-2012"))
			{
				cmsTest("GOST-3410-2012", "Tc26-Gost-3410-12-512-paramSetA", "GOST3411-2012-512WITHECGOST3410-2012-512", RosstandartObjectIdentifiers_Fields.id_tc26_gost_3411_12_512.getId());
				cmsTest("GOST-3410-2012", "Tc26-Gost-3410-12-512-paramSetB", "GOST3411-2012-512WITHECGOST3410-2012-512", RosstandartObjectIdentifiers_Fields.id_tc26_gost_3411_12_512.getId());
				cmsTest("GOST-3410-2012", "Tc26-Gost-3410-12-512-paramSetC", "GOST3411-2012-512WITHECGOST3410-2012-512", RosstandartObjectIdentifiers_Fields.id_tc26_gost_3411_12_512.getId());
				cmsTest("GOST-3410-2012", "Tc26-Gost-3410-12-256-paramSetA", "GOST3411-2012-256WITHECGOST3410-2012-256", RosstandartObjectIdentifiers_Fields.id_tc26_gost_3411_12_256.getId());
			}
		}

		public virtual void cmsTest(string keyAlgorithm, string paramName, string signAlgorithm, string digestId)
		{
			try
			{
				KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyAlgorithm, "BC");
				keyPairGenerator.initialize(new ECNamedCurveGenParameterSpec(paramName), new SecureRandom());
				KeyPair keyPair = keyPairGenerator.generateKeyPair();

				X509CertificateHolder signingCertificate = selfSignedCertificate(keyPair, signAlgorithm);

				// CMS
				byte[] dataContent = new byte[]{1, 2, 3, 4, 33, 22, 11, 33, 52, 21, 23};
				CMSTypedData cmsTypedData = new CMSProcessableByteArray(dataContent);


//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder signerInfoGeneratorBuilder = new org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder(new org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder().setProvider("BC").build());
				JcaSignerInfoGeneratorBuilder signerInfoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder((new JcaDigestCalculatorProviderBuilder()).setProvider("BC").build());

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.operator.ContentSigner contentSigner = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(signAlgorithm).setProvider("BC").build(keyPair.getPrivate());
				ContentSigner contentSigner = (new JcaContentSignerBuilder(signAlgorithm)).setProvider("BC").build(keyPair.getPrivate());

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.cms.SignerInfoGenerator signerInfoGenerator = signerInfoGeneratorBuilder.build(contentSigner, signingCertificate);
				SignerInfoGenerator signerInfoGenerator = signerInfoGeneratorBuilder.build(contentSigner, signingCertificate);

				CMSSignedDataGenerator cmsSignedDataGenerator = new CMSSignedDataGenerator();

				cmsSignedDataGenerator.addCertificate(signingCertificate);
				cmsSignedDataGenerator.addSignerInfoGenerator(signerInfoGenerator);

				CMSSignedData cmsSignedData = cmsSignedDataGenerator.generate(cmsTypedData, false);
				if (cmsSignedData == null)
				{
					fail("Cant create CMS");
				}

				bool algIdContains = false;
				for (Iterator it = cmsSignedData.getDigestAlgorithmIDs().iterator(); it.hasNext();)
				{
					AlgorithmIdentifier algorithmIdentifier = (AlgorithmIdentifier)it.next();
					if (algorithmIdentifier.getAlgorithm().getId().Equals(digestId))
					{
						algIdContains = true;
						break;
					}
				}
				if (!algIdContains)
				{
					fail("identifier not valid");
				}
				bool result = verify(cmsSignedData, cmsTypedData);
				if (!result)
				{
					fail("Verification fails ");
				}

			}
			catch (Exception ex)
			{
				Console.WriteLine(ex.ToString());
				Console.Write(ex.StackTrace);
				fail("fail with exception:", ex);
			}
		}

		private bool verify(CMSSignedData signature, CMSTypedData typedData)
		{
			CMSSignedData signedDataToVerify = new CMSSignedData(typedData, signature.getEncoded());
			Store certs = signedDataToVerify.getCertificates();
			SignerInformationStore signers = signedDataToVerify.getSignerInfos();
			Collection<SignerInformation> c = signers.getSigners();
			for (Iterator it = c.iterator(); it.hasNext();)
			{
				SignerInformation signer = (SignerInformation)it.next();
				SignerId signerId = signer.getSID();
				Collection certCollection = certs.getMatches(signerId);

				Iterator certIt = certCollection.iterator();
				object certificate = certIt.next();
				SignerInformationVerifier verifier = (new JcaSimpleSignerInfoVerifierBuilder()).setProvider("BC").build((X509CertificateHolder)certificate);


				bool result = signer.verify(verifier);
				if (result)
				{
					return true;
				}
			}
			return false;
		}

		private X509CertificateHolder selfSignedCertificate(KeyPair keyPair, string signatureAlgName)
		{

			X500Name name = new X500Name("CN=BB, C=aa");
			ECPublicKey k = (ECPublicKey)keyPair.getPublic();
			ECParameterSpec s = k.getParameters();
			ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(k.getQ(), new ECDomainParameters(s.getCurve(), s.getG(), s.getN()));

			ECPrivateKey kk = (ECPrivateKey)keyPair.getPrivate();
			ECParameterSpec ss = kk.getParameters();

			ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(kk.getD(), new ECDomainParameters(ss.getCurve(), ss.getG(), ss.getN()));

			AsymmetricKeyParameter publicKey = ecPublicKeyParameters;
			AsymmetricKeyParameter privateKey = ecPrivateKeyParameters;
			X509v3CertificateBuilder myCertificateGenerator = new X509v3CertificateBuilder(name, BigInteger.ONE, DateTime.Now, new DateTime((DateTime.Now).Ticks + 364 * 50 * 3600), name, SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey));

			DefaultSignatureAlgorithmIdentifierFinder signatureAlgorithmIdentifierFinder = new DefaultSignatureAlgorithmIdentifierFinder();
			DefaultDigestAlgorithmIdentifierFinder digestAlgorithmIdentifierFinder = new DefaultDigestAlgorithmIdentifierFinder();

			AlgorithmIdentifier signAlgId = signatureAlgorithmIdentifierFinder.find(signatureAlgName);
			AlgorithmIdentifier digestAlgId = digestAlgorithmIdentifierFinder.find(signAlgId);

			BcContentSignerBuilder signerBuilder = new BcECContentSignerBuilder(signAlgId, digestAlgId);

			int val = KeyUsage.cRLSign;
			val = val | KeyUsage.dataEncipherment;
			val = val | KeyUsage.decipherOnly;
			val = val | KeyUsage.digitalSignature;
			val = val | KeyUsage.encipherOnly;
			val = val | KeyUsage.keyAgreement;
			val = val | KeyUsage.keyEncipherment;
			val = val | KeyUsage.nonRepudiation;
			myCertificateGenerator.addExtension(Extension.keyUsage, true, new KeyUsage(val));

			myCertificateGenerator.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

			myCertificateGenerator.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));


			X509CertificateHolder holder = myCertificateGenerator.build(signerBuilder.build(privateKey));

			return holder;
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());
			Test test = new GOST3410_2012CMSTest();
			TestResult result = test.perform();
			JavaSystem.@out.println(result);
		}
	}

}
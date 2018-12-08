using org.bouncycastle.asn1.eac;

namespace org.bouncycastle.eac.test
{

	using Test = junit.framework.Test;
	using TestCase = junit.framework.TestCase;
	using TestSuite = junit.framework.TestSuite;
	using CertificateHolderAuthorization = org.bouncycastle.asn1.eac.CertificateHolderAuthorization;
	using CertificateHolderReference = org.bouncycastle.asn1.eac.CertificateHolderReference;
	using CertificationAuthorityReference = org.bouncycastle.asn1.eac.CertificationAuthorityReference;
	using EACObjectIdentifiers = org.bouncycastle.asn1.eac.EACObjectIdentifiers;
	using PackedDate = org.bouncycastle.asn1.eac.PackedDate;
	using JcaPublicKeyConverter = org.bouncycastle.eac.jcajce.JcaPublicKeyConverter;
	using EACSignatureVerifier = org.bouncycastle.eac.@operator.EACSignatureVerifier;
	using EACSigner = org.bouncycastle.eac.@operator.EACSigner;
	using JcaEACSignatureVerifierBuilder = org.bouncycastle.eac.@operator.jcajce.JcaEACSignatureVerifierBuilder;
	using JcaEACSignerBuilder = org.bouncycastle.eac.@operator.jcajce.JcaEACSignerBuilder;
	using ECNamedCurveTable = org.bouncycastle.jce.ECNamedCurveTable;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using ECParameterSpec = org.bouncycastle.jce.spec.ECParameterSpec;
	using Arrays = org.bouncycastle.util.Arrays;
	using Streams = org.bouncycastle.util.io.Streams;

	public class AllTests : TestCase
	{
		private const string BC = BouncyCastleProvider.PROVIDER_NAME;

		public virtual void setUp()
		{
			if (Security.getProvider(BC) != null)
			{
				Security.addProvider(new BouncyCastleProvider());
			}
		}

		public virtual void testLoadCertificate()
		{
			EACCertificateHolder certHolder = new EACCertificateHolder(getInput("Belgique CVCA-02032010.7816.cvcert"));

			PublicKey pubKey = (new JcaPublicKeyConverter()).setProvider(BC).getKey(certHolder.getPublicKeyDataObject());
			EACSignatureVerifier verifier = (new JcaEACSignatureVerifierBuilder()).build(certHolder.getPublicKeyDataObject().getUsage(), pubKey);

			if (!certHolder.isSignatureValid(verifier))
			{
				fail("signature test failed");
			}
		}

		private byte[] getInput(string name)
		{
			return Streams.readAll(this.GetType().getResourceAsStream(name));
		}

		public virtual void testLoadInvalidRequest()
		{
			// this request contains invalid unsigned integers (see D 2.1.1)
			EACCertificateRequestHolder requestHolder = new EACCertificateRequestHolder(getInput("REQ_18102010.csr"));

			PublicKey pubKey = (new JcaPublicKeyConverter()).setProvider(BC).getKey(requestHolder.getPublicKeyDataObject());
			EACSignatureVerifier verifier = (new JcaEACSignatureVerifierBuilder()).build(requestHolder.getPublicKeyDataObject().getUsage(), pubKey);

			if (requestHolder.isInnerSignatureValid(verifier))
			{
				fail("signature test failed");
			}
		}

		public virtual void testLoadCSR()
		{
			// this request contains invalid unsigned integers (see D 2.1.1)
			byte[] input = getInput("UTIS00100072.csr");

			EACCertificateRequestHolder requestHolder = new EACCertificateRequestHolder(input);

			PublicKey pubKey = (new JcaPublicKeyConverter()).setProvider(BC).getKey(requestHolder.getPublicKeyDataObject());
			EACSignatureVerifier verifier = (new JcaEACSignatureVerifierBuilder()).build(requestHolder.getPublicKeyDataObject().getUsage(), pubKey);

			TestCase.assertTrue("signature test failed", requestHolder.isInnerSignatureValid(verifier));
			TestCase.assertTrue("comparison failed", Arrays.areEqual(input, requestHolder.toASN1Structure().getEncoded()));
		}

		public virtual void testLoadRefCert()
		{
			EACCertificateHolder certHolder = new EACCertificateHolder(getInput("at_cert_19a.cvcert"));


		}

		public virtual void testGenerateEC()
		{
			ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
			KeyPair kp = generateECKeyPair(ecSpec);

			JcaEACSignerBuilder signerBuilder = (new JcaEACSignerBuilder()).setProvider(BC);

			EACSigner signer = signerBuilder.build("SHA256withECDSA", kp.getPrivate());

			int role = CertificateHolderAuthorization.CVCA;
			int rights = CertificateHolderAuthorization.RADG3 | CertificateHolderAuthorization.RADG4;

			EACCertificateBuilder certBuilder = new EACCertificateBuilder(new CertificationAuthorityReference("AU", "BC TEST", "12345"), (new JcaPublicKeyConverter()).getPublicKeyDataObject(signer.getUsageIdentifier(), kp.getPublic()), new CertificateHolderReference("AU", "BC TEST", "12345"), new CertificateHolderAuthorization(EACObjectIdentifiers_Fields.id_EAC_ePassport, role | rights), new PackedDate("110101"), new PackedDate("120101"));

			EACCertificateHolder certHolder = certBuilder.build(signer);

			EACSignatureVerifier verifier = (new JcaEACSignatureVerifierBuilder()).build(certHolder.getPublicKeyDataObject().getUsage(), kp.getPublic());

			if (!certHolder.isSignatureValid(verifier))
			{
				fail("first signature test failed");
			}

			PublicKey pubKey = (new JcaPublicKeyConverter()).setProvider(BC).getKey(certHolder.getPublicKeyDataObject());
			verifier = (new JcaEACSignatureVerifierBuilder()).build(certHolder.getPublicKeyDataObject().getUsage(), pubKey);

			if (!certHolder.isSignatureValid(verifier))
			{
				fail("second signature test failed");
			}
		}

		public virtual void testGenerateRSA()
		{
			KeyPair kp = generateRSAKeyPair();

			JcaEACSignerBuilder signerBuilder = (new JcaEACSignerBuilder()).setProvider(BC);

			EACSigner signer = signerBuilder.build("SHA256withRSA", kp.getPrivate());

			int role = CertificateHolderAuthorization.CVCA;
			int rights = CertificateHolderAuthorization.RADG3 | CertificateHolderAuthorization.RADG4;

			EACCertificateBuilder certBuilder = new EACCertificateBuilder(new CertificationAuthorityReference("AU", "BC TEST", "12345"), (new JcaPublicKeyConverter()).getPublicKeyDataObject(signer.getUsageIdentifier(), kp.getPublic()), new CertificateHolderReference("AU", "BC TEST", "12345"), new CertificateHolderAuthorization(EACObjectIdentifiers_Fields.id_EAC_ePassport, role | rights), new PackedDate("110101"), new PackedDate("120101"));

			EACCertificateHolder certHolder = certBuilder.build(signer);

			EACSignatureVerifier verifier = (new JcaEACSignatureVerifierBuilder()).build(certHolder.getPublicKeyDataObject().getUsage(), kp.getPublic());

			if (!certHolder.isSignatureValid(verifier))
			{
				fail("first signature test failed");
			}

			PublicKey pubKey = (new JcaPublicKeyConverter()).setProvider(BC).getKey(certHolder.getPublicKeyDataObject());
			verifier = (new JcaEACSignatureVerifierBuilder()).build(certHolder.getPublicKeyDataObject().getUsage(), pubKey);

			if (!certHolder.isSignatureValid(verifier))
			{
				fail("second signature test failed");
			}
		}

		private KeyPair generateECKeyPair(ECParameterSpec spec)
		{
			KeyPairGenerator gen = KeyPairGenerator.getInstance("ECDSA",BC);

			gen.initialize(spec, new SecureRandom());

			KeyPair generatedKeyPair = gen.generateKeyPair();
			return generatedKeyPair;
		}

		private KeyPair generateRSAKeyPair()
		{
			KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA",BC);

			gen.initialize(1024, new SecureRandom());

			KeyPair generatedKeyPair = gen.generateKeyPair();
			return generatedKeyPair;
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			junit.textui.TestRunner.run(suite());
		}

		public static Test suite()
		{
			TestSuite suite = new TestSuite("EAC tests");

			suite.addTestSuite(typeof(AllTests));

			return new EACTestSetup(suite);
		}
	}

}
using System;

namespace org.bouncycastle.jce.provider.test
{

	using Test = org.bouncycastle.util.test.Test;
	using TestResult = org.bouncycastle.util.test.TestResult;

	public class RegressionTest
	{
		public static Test[] tests = new Test[]
		{
			new FIPSDESTest(),
			new DESedeTest(),
			new AESTest(),
			new AEADTest(),
			new CamelliaTest(),
			new SEEDTest(),
			new AESSICTest(),
			new GOST28147Test(),
			new PBETest(),
			new BlockCipherTest(),
			new MacTest(),
			new HMacTest(),
			new SealedTest(),
			new RSATest(),
			new DHTest(),
			new DHIESTest(),
			new DSATest(),
			new ImplicitlyCaTest(),
			new ECNRTest(),
			new ECIESTest(),
			new ECIESVectorTest(),
			new ECDSA5Test(),
			new GOST3410Test(),
			new ElGamalTest(),
			new IESTest(),
			new SigTest(),
			new CertTest(),
			new PKCS10CertRequestTest(),
			new EncryptedPrivateKeyInfoTest(),
			new KeyStoreTest(),
			new PKCS12StoreTest(),
			new DigestTest(),
			new PSSTest(),
			new WrapTest(),
			new DoFinalTest(),
			new CipherStreamTest(),
			new CipherStreamTest2(),
			new NamedCurveTest(),
			new PKIXTest(),
			new NetscapeCertRequestTest(),
			new X509StreamParserTest(),
			new X509CertificatePairTest(),
			new CertPathTest(),
			new CertStoreTest(),
			new CertPathValidatorTest(),
			new CertPathBuilderTest(),
			new ECEncodingTest(),
			new AlgorithmParametersTest(),
			new NISTCertPathTest(),
			new PKIXPolicyMappingTest(),
			new SlotTwoTest(),
			new PKIXNameConstraintsTest(),
			new MultiCertStoreTest(),
			new NoekeonTest(),
			new SerialisationTest(),
			new SigNameTest(),
			new MQVTest(),
			new CMacTest(),
			new GMacTest(),
			new OCBTest(),
			new DSTU4145Test(),
			new CRL5Test(),
			new Poly1305Test(),
			new SipHashTest(),
			new KeccakTest(),
			new SkeinTest(),
			new Shacal2Test(),
			new DetDSATest(),
			new ThreefishTest(),
			new SM2SignatureTest(),
			new SM4Test(),
			new TLSKDFTest(),
			new BCFKSStoreTest(),
			new DSTU7624Test(),
			new GOST3412Test(),
			new GOST3410KeyPairTest(),
			new EdECTest(),
			new OpenSSHSpecTests()
		};

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			JavaSystem.@out.println("Testing " + Security.getProvider("BC").getInfo() + " version: " + Security.getProvider("BC").getVersion());

			for (int i = 0; i != tests.Length; i++)
			{
				TestResult result = tests[i].perform();

				if (result.getException() != null)
				{
					Console.WriteLine(result.getException().ToString());
					Console.Write(result.getException().StackTrace);
				}

				JavaSystem.@out.println(result);
			}
		}
	}


}